import time

from ..core.base_detector import BaseDetector
from ..payloads.sqli import (
    BOOLEAN_PAIRS,
    DBMS_ERROR_PATTERNS,
    TIME_PAYLOADS,
    all_error_payloads,
    STACKED_PROBE_PAYLOADS,
    UNION_PROBE_PAYLOADS,
)


class SQLIDetector(BaseDetector):
    """SQLMap-inspired SQLi tespiti — WAF-aware, stacked, union, blind, waktu."""

    def __init__(self, session=None, timeout=8, ai_engine=None, mode='fast', custom_payloads=None, stealth=True):
        if mode == 'fast':
            timeout = 5
        super().__init__(session, timeout, ai_engine, mode, custom_payloads, stealth)
        all_payloads = list(all_error_payloads())
        if self.mode == 'fast':
            self.error_payloads = all_payloads[:10]
        elif self.mode == 'fuzz':
            self.error_payloads = all_payloads[:200]
        else:
            self.error_payloads = all_payloads[:40]

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

                    # WAF block kontrolü
                    if self._is_waf_blocking(resp):
                        # WAF bypass dene
                        for bp_resp, bp_elapsed, bp_url, bp_payload in self._request_with_bypass(
                            endpoint, param, payload, 'sqli'
                        ):
                            if not self._is_waf_blocking(bp_resp):
                                matched = self.analyzer.match_regex(bp_resp.text, DBMS_ERROR_PATTERNS)
                                if matched:
                                    results.append(self._make_result(
                                        'sqli', bp_url, param, bp_payload, 'high', 'error-based-waf-bypass',
                                        hint=f'WAF bypass ile SQL hatası tespit edildi ({matched}). sqlmap -u "{bp_url}" -p {param} --tamper=space2comment --batch ile doğrulayın',
                                    ))
                                    found_techniques.add('error')
                                    break
                        continue

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

            # Phase 2: Boolean blind
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

                        if self._is_waf_blocking(true_resp) or self._is_waf_blocking(false_resp):
                            continue

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

            # Phase 3: Time-based
            if 'time' not in found_techniques:
                for payload, dbms in TIME_PAYLOADS[:6]:
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

            # Phase 4: Stacked queries
            if 'stacked' not in found_techniques:
                for payload in STACKED_PROBE_PAYLOADS[:8]:
                    try:
                        if method == 'GET':
                            resp, _, url = self._request_get(endpoint, param, payload)
                        else:
                            resp, _ = self._request_post(endpoint, param, payload)
                            url = endpoint['url']

                        if self._is_waf_blocking(resp):
                            continue

                        if resp.status_code == 200 and len(resp.text) > 0:
                            if self.analyzer.significant_diff(baseline_body, resp.text):
                                results.append(self._make_result(
                                    'sqli', url, param, payload, 'low', 'stacked-query',
                                    hint=f'Stacked query sinyali — sqlmap -u "{url}" -p {param} --technique=S --batch ile test edin',
                                ))
                                found_techniques.add('stacked')
                                break
                    except Exception:
                        continue

            # Phase 5: UNION-based column count
            if 'union' not in found_techniques:
                for payload in UNION_PROBE_PAYLOADS[:6]:
                    try:
                        if method == 'GET':
                            resp, _, url = self._request_get(endpoint, param, payload)
                        else:
                            resp, _ = self._request_post(endpoint, param, payload)
                            url = endpoint['url']

                        if self._is_waf_blocking(resp):
                            continue

                        matched = self.analyzer.match_regex(resp.text, DBMS_ERROR_PATTERNS)
                        if matched and 'column' in matched.lower():
                            results.append(self._make_result(
                                'sqli', url, param, payload, 'medium', 'union-column-count',
                                hint=f'UNION sütun sayısı sinyali. sqlmap -u "{url}" -p {param} --technique=U --batch ile test edin',
                            ))
                            found_techniques.add('union')
                            break
                    except Exception:
                        continue

            # Phase 6: WAF-aware bypass denemesi
            if self.detected_wafs and self.detected_wafs != ["unknown"]:
                if not found_techniques:
                    waf_bypass_payloads = [
                        "' OR '1'='1", "' AND '1'='1", "1' OR '1'='1",
                    ]
                    for wb_payload in waf_bypass_payloads:
                        for bp_resp, bp_elapsed, bp_url, bp_payload in self._request_with_bypass(
                            endpoint, param, wb_payload, 'sqli'
                        ):
                            if not self._is_waf_blocking(bp_resp):
                                matched = self.analyzer.match_regex(bp_resp.text, DBMS_ERROR_PATTERNS)
                                if matched:
                                    results.append(self._make_result(
                                        'sqli', bp_url, param, bp_payload, 'high', 'waf-bypass-error',
                                        hint=f'WAF bypass ile SQL hatası ({matched}). sqlmap -u "{bp_url}" -p {param} --tamper=space2comment,randomcase --batch ile doğrulayın',
                                    ))
                                    found_techniques.add('waf-bypass')
                                    break
                        if 'waf-bypass' in found_techniques:
                            break

        return results
