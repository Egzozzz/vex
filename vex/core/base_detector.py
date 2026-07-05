import time
from urllib.parse import parse_qs, urlencode, urlparse

import requests

from .response_analyzer import ResponseAnalyzer
from .ai_engine import AIEngine


class BaseDetector:
    """Tüm dedektörler için ortak HTTP test altyapısı."""

    MANUAL_HINTS = {
        'sqli': 'sqlmap -u "{url}" -p {param} --batch --level=1 --risk=1 ile doğrulayın',
        'xss': 'Dalfox/XSStrike ile manuel doğrulama yapın: dalfox url "{url}"',
        'ssrf': 'SSRFmap ile iç ağ/metadata erişimini manuel test edin',
        'rce': 'Komut enjeksiyonunu kontrollü ortamda manuel doğrulayın',
        'xxe': 'XXE payload\'ını Burp/Repeater ile XML endpoint\'inde test edin',
        'path_traversal': 'Path traversal için dosya okuma payload\'larını manuel deneyin',
        'bac': 'Yetkisiz admin panel erişimini farklı kullanıcı oturumlarıyla doğrulayın',
        'idor': 'Farklı kullanıcı oturumlarıyla ID değerlerini manuel karşılaştırın',
    }

    def __init__(self, session=None, timeout=8, ai_engine=None, mode='fast', custom_payloads=None):
        self.session = session or requests.Session()
        self.timeout = timeout
        self.analyzer = ResponseAnalyzer()
        self.ai_engine = ai_engine
        self.mode = mode
        self.custom_payloads = custom_payloads or {}


    def _default_hint(self, vuln_type, url='', param=''):
        template = self.MANUAL_HINTS.get(vuln_type, 'Manuel doğrulama önerilir')
        return template.format(url=url, param=param)

    def _build_params(self, endpoint, param, value):
        parsed = urlparse(endpoint['url'])
        if 'query_params' in endpoint:
            params = {k: (v[0] if isinstance(v, list) and v else v) for k, v in endpoint['query_params'].items()}
        else:
            params = {k: v[0] if isinstance(v, list) and v else v for k, v in parse_qs(parsed.query).items()}
        params[param] = value
        return params

    def _baseline_get(self, endpoint):
        parsed = urlparse(endpoint['url'])
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = self._build_params(endpoint, endpoint['params'][0], 'test')
        for p in endpoint['params']:
            if p not in params:
                params[p] = 'test'
        url = f"{base_url}?{urlencode(params)}"
        start = time.time()
        resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
        return resp, time.time() - start, url

    def _request_get(self, endpoint, param, payload):
        parsed = urlparse(endpoint['url'])
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = self._build_params(endpoint, param, payload)
        url = f"{base_url}?{urlencode(params)}"
        start = time.time()
        resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
        return resp, time.time() - start, url

    def _request_post(self, endpoint, param, payload):
        data = {p: 'test' for p in endpoint['params']}
        data[param] = payload
        method = endpoint.get('method', 'POST')
        start = time.time()
        if method == 'POST':
            resp = self.session.post(endpoint['url'], data=data, timeout=self.timeout, allow_redirects=True)
        else:
            resp = self.session.request(method, endpoint['url'], data=data, timeout=self.timeout, allow_redirects=True)
        return resp, time.time() - start

    def _make_result(self, vuln_type, url, param, payload, confidence, technique, hint=None, **extra):
        result = {
            'type': vuln_type,
            'url': url,
            'param': param,
            'payload': payload,
            'confidence': confidence,
            'technique': technique,
            'manual_test': hint or self._default_hint(vuln_type, url=url, param=param),
        }
        result.update(extra)
        return result

    def _iterate_params(self, endpoint):
        if not endpoint or not endpoint.get('params'):
            return
        method = endpoint.get('method', 'GET')
        for param in endpoint['params']:
            yield param, method
