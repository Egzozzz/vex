import time
import random
from urllib.parse import parse_qs, urlencode, urlparse

import requests

from .response_analyzer import ResponseAnalyzer
from .ai_engine import AIEngine
from .stealth import StealthEngine
from ..payloads.waf import (
    detect_waf, generate_bypass_payloads, get_random_headers, random_delay,
    get_waf_bypass_headers, get_rate_limit_delay,
)


class BaseDetector:
    """Tüm dedektörler için ortak HTTP test altyapısı — WAF-aware + stealth."""

    MANUAL_HINTS = {
        'sqli': 'sqlmap -u "{url}" -p {param} --batch --level=3 --risk=2 ile doğrulayın',
        'xss': 'Dalfox/XSStrike ile manuel doğrulama yapın: dalfox url "{url}" -p {param}',
        'ssrf': 'SSRFmap ile iç ağ/metadata erişimini manuel test edin',
        'rce': 'Commix ile komut enjeksiyonunu test edin: commix -u "{url}" --data="{param}=*"',
        'xxe': 'XXE payload\'ını Burp/Repeater ile XML endpoint\'inde test edin',
        'path_traversal': 'Path traversal için dotdotpwn ile test edin: dotdotpwn -m http -u "{url}"',
        'bac': 'Yetkisiz admin panel erişimini farklı kullanıcı oturumlarıyla doğrulayın',
        'idor': 'Farklı kullanıcı oturumlarıyla ID değerlerini manuel karşılaştırın',
    }

    HIGH_PRIORITY_PARAMS = [
        'id', 'uid', 'user_id', 'user', 'q', 'query', 'search', 's',
        'order', 'sort', 'page', 'limit', 'offset', 'start', 'end',
        'from', 'to', 'date', 'time', 'datetime', 'timestamp',
        'email', 'username', 'name', 'password', 'pass',
        'url', 'uri', 'link', 'src', 'source', 'dest', 'destination',
        'redirect', 'next', 'return', 'callback', 'file', 'document',
        'path', 'folder', 'root', 'feed', 'host', 'site',
        'action', 'cmd', 'command', 'execute', 'run', 'exec',
        'data', 'xml', 'json', 'payload', 'input', 'text', 'content',
    ]

    def __init__(self, session=None, timeout=8, ai_engine=None, mode='fast',
                 custom_payloads=None, stealth=True):
        self.session = session or requests.Session()
        self.timeout = timeout
        self.analyzer = ResponseAnalyzer()
        self.ai_engine = ai_engine
        self.mode = mode
        self.custom_payloads = custom_payloads or {}
        self.stealth = stealth
        self.detected_wafs = []
        self._stealth_engine = None
        self._init_stealth_session()

    def _init_stealth_session(self):
        """Stealth mod için session'ı yapılandır."""
        if self.stealth:
            self.session.headers.update(get_random_headers())

    def _configure_stealth(self, stealth_engine):
        """Dış stealth motorunu entegre et."""
        self._stealth_engine = stealth_engine
        if stealth_engine:
            stealth_engine.configure_session(self.session)

    def _update_stealth_headers(self):
        """Stealth mod için header'ları yenile."""
        if self.stealth and random.random() < 0.15:
            if self._stealth_engine:
                self._stealth_engine.rotate_headers(self.session)
            else:
                self.session.headers.update(get_random_headers())

    def _wait(self):
        """Stealth mod için rastgele bekleme."""
        if self.stealth:
            if self._stealth_engine:
                time.sleep(self._stealth_engine.get_delay())
            else:
                time.sleep(random_delay())

    def _default_hint(self, vuln_type, url='', param=''):
        template = self.MANUAL_HINTS.get(vuln_type, 'Manuel doğrulama önerilir')
        return template.format(url=url, param=param)

    def _build_params(self, endpoint, param, value):
        parsed = urlparse(endpoint['url'])
        if 'query_params' in endpoint:
            params = {k: (v[0] if isinstance(v, list) and v else v)
                      for k, v in endpoint['query_params'].items()}
        else:
            params = {k: v[0] if isinstance(v, list) and v else v
                      for k, v in parse_qs(parsed.query).items()}
        params[param] = value
        return params

    def _baseline_get(self, endpoint):
        self._wait()
        self._update_stealth_headers()
        parsed = urlparse(endpoint['url'])
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = self._build_params(endpoint, endpoint['params'][0], 'test')
        for p in endpoint['params']:
            if p not in params:
                params[p] = 'test'
        url = f"{base_url}?{urlencode(params)}"
        start = time.time()
        resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
        self._detect_waf(resp)
        return resp, time.time() - start, url

    def _request_get(self, endpoint, param, payload):
        self._wait()
        self._update_stealth_headers()
        parsed = urlparse(endpoint['url'])
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = self._build_params(endpoint, param, payload)
        url = f"{base_url}?{urlencode(params)}"
        start = time.time()
        resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
        self._detect_waf(resp)

        if self._stealth_engine and self._stealth_engine.is_rate_limited(resp):
            self._wait()
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)

        if self._stealth_engine:
            self._stealth_engine.handle_waf_block(resp, self.session)

        return resp, time.time() - start, url

    def _request_post(self, endpoint, param, payload):
        self._wait()
        self._update_stealth_headers()
        data = {p: 'test' for p in endpoint['params']}
        data[param] = payload
        method = endpoint.get('method', 'POST')
        start = time.time()
        if method == 'POST':
            resp = self.session.post(endpoint['url'], data=data,
                                     timeout=self.timeout, allow_redirects=True)
        else:
            resp = self.session.request(method, endpoint['url'], data=data,
                                        timeout=self.timeout, allow_redirects=True)
        self._detect_waf(resp)

        if self._stealth_engine and self._stealth_engine.is_rate_limited(resp):
            self._wait()
            if method == 'POST':
                resp = self.session.post(endpoint['url'], data=data,
                                         timeout=self.timeout, allow_redirects=True)
            else:
                resp = self.session.request(method, endpoint['url'], data=data,
                                            timeout=self.timeout, allow_redirects=True)

        if self._stealth_engine:
            self._stealth_engine.handle_waf_block(resp, self.session)

        return resp, time.time() - start

    def _request_with_bypass(self, endpoint, param, payload, vuln_type):
        """WAF bypass payload'ları ile istek gönder."""
        bypass_payloads = generate_bypass_payloads(payload, vuln_type)
        for bp in bypass_payloads[:10]:
            try:
                if endpoint.get('method', 'GET') == 'GET':
                    resp, elapsed, url = self._request_get(endpoint, param, bp)
                else:
                    resp, elapsed = self._request_post(endpoint, param, bp)
                    url = endpoint['url']
                yield resp, elapsed, url, bp
            except Exception:
                continue

    def _detect_waf(self, response):
        """Yanıttan WAF'ı algıla."""
        new_wafs = detect_waf(
            headers=response.headers,
            status_code=response.status_code,
            content=response.text
        )
        if new_wafs and new_wafs != ["unknown"]:
            for w in new_wafs:
                if w not in self.detected_wafs:
                    self.detected_wafs.append(w)

    def _make_result(self, vuln_type, url, param, payload, confidence, technique, hint=None, **extra):
        result = {
            'type': vuln_type,
            'url': url,
            'param': param,
            'payload': payload,
            'confidence': confidence,
            'technique': technique,
            'manual_test': hint or self._default_hint(vuln_type, url=url, param=param),
            'detected_wafs': self.detected_wafs,
        }
        result.update(extra)
        return result

    def _get_param_priority(self, param):
        param_lower = param.lower()
        if any(hint in param_lower for hint in self.HIGH_PRIORITY_PARAMS):
            return 2
        if len(param) <= 5:
            return 1
        return 0

    def _iterate_params(self, endpoint):
        if not endpoint or not endpoint.get('params'):
            return
        method = endpoint.get('method', 'GET')
        sorted_params = sorted(
            endpoint['params'],
            key=lambda p: -self._get_param_priority(p)
        )
        # Fast modda sadece ilk 2 parametreyi test et
        max_params = 2 if self.mode == 'fast' else len(sorted_params)
        for param in sorted_params[:max_params]:
            yield param, method

    def _get_bypass_payloads(self, base_payload, vuln_type):
        return generate_bypass_payloads(base_payload, vuln_type)

    def _is_waf_blocking(self, response):
        """WAF'ın isteği engelleyip engellemediğini kontrol et."""
        if response.status_code in (403, 406, 429, 503):
            return True
        blocking_indicators = [
            'access denied', 'forbidden', 'blocked', 'security violation',
            'waf', 'firewall', 'request rejected',
        ]
        text_lower = (response.text or '').lower()
        return any(ind in text_lower for ind in blocking_indicators)

    def _try_waf_bypass(self, endpoint, param, payload, vuln_type, check_fn):
        """WAF block varsa bypass payload'larıyla dene."""
        for resp, elapsed, url, bp in self._request_with_bypass(endpoint, param, payload, vuln_type):
            if check_fn(resp, elapsed):
                return resp, elapsed, url, bp
        return None, None, None, None
