import hashlib
import re
from difflib import SequenceMatcher


class ResponseAnalyzer:
    """SQLMap/Dalfox/Nuclei tarzı yanıt analizi — sömürü değil, sinyal tespiti."""

    @staticmethod
    def body_hash(text):
        return hashlib.md5((text or '').encode('utf-8', errors='ignore')).hexdigest()

    @staticmethod
    def content_length(text):
        return len(text or '')

    @staticmethod
    def similarity(a, b):
        return SequenceMatcher(None, a or '', b or '').ratio()

    @staticmethod
    def significant_diff(baseline, test, threshold=0.02):
        if baseline is None or test is None:
            return False
        len_a = len(baseline)
        len_b = len(test)
        if len_a == 0 and len_b == 0:
            return False
        if abs(len_a - len_b) / max(len_a, len_b, 1) > threshold:
            return True
        return ResponseAnalyzer.similarity(baseline, test) < (1 - threshold)

    @staticmethod
    def boolean_blind_signal(true_body, false_body, baseline_body):
        true_diff = ResponseAnalyzer.significant_diff(baseline_body, true_body)
        false_diff = ResponseAnalyzer.significant_diff(baseline_body, false_body)
        true_false_diff = ResponseAnalyzer.significant_diff(true_body, false_body)
        return true_diff and false_diff and true_false_diff

    @staticmethod
    def match_any(text, patterns, case_insensitive=True):
        if not text:
            return None
        haystack = text.lower() if case_insensitive else text
        for pattern in patterns:
            if case_insensitive:
                if pattern.lower() in haystack:
                    return pattern
            elif pattern in text:
                return pattern
        return None

    @staticmethod
    def match_regex(text, patterns):
        if not text:
            return None
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return pattern
        return None

    @staticmethod
    def timing_anomaly(elapsed, baseline_elapsed, threshold=3.5):
        return elapsed >= threshold and elapsed > (baseline_elapsed * 2 + 2)

    @staticmethod
    def reflected_marker(body, marker):
        if not body or not marker:
            return False
        return marker in body

    @staticmethod
    def reflected_partial(body, marker):
        if not body or not marker:
            return False
        if marker in body:
            return True
        stripped = re.sub(r'[<>"\'\s/\\]', '', marker)
        return stripped and stripped in re.sub(r'[<>"\'\s/\\]', '', body)
