import time

from ..core.base_detector import BaseDetector
from ..payloads.sqli import (
    BOOLEAN_PAIRS,
    DBMS_ERROR_PATTERNS,
    TIME_PAYLOADS,
    all_error_payloads,
)


class SQLIDetector(BaseDetector):
    """SQLMap-inspired SQLi tespiti — sömürü yok, manuel doğrulama önerisi."""

    def __init__(self, session=None, timeout=8, ai_engine=None, mode='fast', custom_payloads=None):
        super().__init__(session, timeout, ai_engine, mode, custom_payloads)
        self.error_payloads = list(all_error_payloads())

    def test(self, endpoint):
        results = []
        if not endpoint or not endpoint.get('params'):
            return results

        method = endpoint.get('method', 'GET')
        baseline_body = ''
        baseline_time = 0.0

        try:
            if method == 'GET':
                baseline_resp, baseline_time, _ = self._baseline_get(endpoint)
                baseline_body = baseline_resp.text
        except Exception:
            pass

        for param, method in self._iterate_params(endpoint):
            found_techniques = set()

            # Phase 1: Error-based (SQLMap errors.xml imzaları)
            for payload in self.error_payloads:
                if 'error' in found_techniques:
                    break
                try:
                    if method == 'GET':
                        resp, _, url = self._request_get(endpoint, param, payload)
                    else:
                        resp, _ = self._request_post(endpoint, param, payload)
                        url = endpoint['url']

                    matched = self.analyzer.match_regex(resp.text, DBMS_ERROR_PATTERNS)
                    if matched:
                        results.append(self._make_result(
                            'sqli', url, param, payload, 'high', 'error-based',
                            hint=f'SQL hatası tespit edildi ({matched}). sqlmap -u "{url}" -p {param} --batch ile doğrulayın',
                        ))
                        found_techniques.add('error')
                        break
                except Exception:
                    continue

            # Phase 2: Boolean blind (SQLMap true/false karşılaştırma)
            if 'boolean' not in found_techniques and baseline_body:
                for true_p, false_p in BOOLEAN_PAIRS:
                    try:
                        if method == 'GET':
                            true_resp, _, url = self._request_get(endpoint, param, true_p)
                            false_resp, _, _ = self._request_get(endpoint, param, false_p)
                        else:
                            true_resp, _ = self._request_post(endpoint, param, true_p)
                            false_resp, _ = self._request_post(endpoint, param, false_p)
                            url = endpoint['url']

                        if self.analyzer.boolean_blind_signal(
                            true_resp.text, false_resp.text, baseline_body
                        ):
                            results.append(self._make_result(
                                'sqli', url, param, true_p, 'medium', 'boolean-blind',
                                hint=f'True/false yanıt farkı var. sqlmap -u "{url}" -p {param} --technique=B --batch ile test edin',
                            ))
                            found_techniques.add('boolean')
                            break
                    except Exception:
                        continue

            # Phase 3: Time-based hint (SQLMap — sadece gecikme sinyali)
            if 'time' not in found_techniques:
                for payload, dbms in TIME_PAYLOADS[:4]:
                    try:
                        if method == 'GET':
                            _, elapsed, url = self._request_get(endpoint, param, payload)
                        else:
                            _, elapsed = self._request_post(endpoint, param, payload)
                            url = endpoint['url']

                        if self.analyzer.timing_anomaly(elapsed, baseline_time):
                            results.append(self._make_result(
                                'sqli', url, param, payload, 'low', f'time-based-hint ({dbms})',
                                hint=f'Gecikme sinyali ({elapsed:.1f}s). sqlmap -u "{url}" -p {param} --technique=T --time-sec=5 ile doğrulayın',
                            ))
                            found_techniques.add('time')
                            break
                    except Exception:
                        continue

        return results
