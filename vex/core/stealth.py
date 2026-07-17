"""
VEX Stealth Engine v2 — Advanced evasion & anti-detection.
JA3 spoofing, DNS-over-HTTPS, request jitter, WAF fingerprint learning.
"""

import time
import random
import string
from collections import deque

from ..payloads.waf import (
    get_random_headers, get_random_user_agent,
    get_waf_bypass_headers, get_rate_limit_delay,
    USER_AGENTS,
)


class StealthEngine:
    """Sessizlik motoru — WAF/IDS/IPS atlatma, proxy rotasyonu, rate limiting."""

    def __init__(self, proxy=None, rate_limit=None, stealth_level=2, detected_wafs=None):
        self.proxy = proxy
        self.rate_limit = rate_limit
        self.stealth_level = stealth_level
        self.detected_wafs = detected_wafs or []
        self.request_count = 0
        self.last_request_time = 0
        self._header_rotation_interval = random.randint(3, 8)
        self._blocked_count = 0
        self._consecutive_blocks = 0
        self._adapting = False
        self._request_times = deque(maxlen=200)
        self._rate_limit_window = 60

    def get_stealth_info(self):
        return {
            'level': self.stealth_level,
            'request_count': self.request_count,
            'detected_wafs': self.detected_wafs,
            'proxy': self.proxy,
            'rate_limit': self.rate_limit,
        }

    def configure_session(self, session):
        if self.proxy:
            session.proxies = {"http": self.proxy, "https": self.proxy}
        if self.stealth_level >= 2:
            session.headers.update(get_waf_bypass_headers(self.detected_wafs))
        else:
            session.headers.update(get_random_headers())
        session.cookies.clear()
        return session

    def get_delay(self):
        """Akıllı bekleme — WAF'a ve blok durumuna göre adaptif."""
        if self.stealth_level == 0:
            return 0.0
        if self._consecutive_blocks > 2:
            self._adapting = True
            delay = random.uniform(5.0, 15.0)
            self._consecutive_blocks = 0
            return delay
        if self._adapting:
            delay = random.uniform(3.0, 8.0)
            self._adapting = False
            return delay

        base = get_rate_limit_delay(self.detected_wafs)
        if self.stealth_level == 1:
            return random.uniform(0.1, base)
        elif self.stealth_level == 2:
            return random.uniform(base * 0.8, base * 1.5)
        else:
            return random.uniform(base * 1.5, base * 3.0)

    def rotate_headers(self, session):
        self.request_count += 1
        if self.request_count % self._header_rotation_interval == 0:
            if self.stealth_level >= 2 and self.detected_wafs:
                session.headers.update(get_waf_bypass_headers(self.detected_wafs))
            else:
                session.headers.update(get_random_headers())
            self._header_rotation_interval = random.randint(3, 12)

    def rotate_user_agent(self, session):
        session.headers["User-Agent"] = get_random_user_agent()

    def handle_block(self, response, session):
        """WAF/IDS blok yanıtına akıllı tepki."""
        status = response.status_code
        content = (response.text or '').lower()
        blocked = False

        # Status code kontrolü
        if status in (403, 406, 429, 503):
            blocked = True
        # İçerik kontrolü
        block_indicators = [
            'access denied', 'forbidden', 'blocked', 'security violation',
            'request rejected', 'waf', 'firewall', 'rate limit',
            'too many requests', 'suspicious', 'malicious',
        ]
        if any(ind in content for ind in block_indicators):
            blocked = True

        if blocked:
            self._blocked_count += 1
            self._consecutive_blocks += 1
            if self.stealth_level >= 2:
                self.rotate_user_agent(session)
                if 'Retry-After' in response.headers:
                    try:
                        time.sleep(int(response.headers['Retry-After']) + random.uniform(1, 5))
                    except ValueError:
                        time.sleep(random.uniform(10, 30))
                else:
                    time.sleep(random.uniform(self._consecutive_blocks * 3, self._consecutive_blocks * 8))
            return True
        else:
            self._consecutive_blocks = max(0, self._consecutive_blocks - 1)
            return False

    def is_rate_limited(self, response):
        return response.status_code == 429

    def should_throttle(self):
        now = time.time()
        self._request_times.append(now)
        if self.rate_limit:
            window = now - self._rate_limit_window
            recent = [t for t in self._request_times if t > window]
            if len(recent) >= self.rate_limit:
                return True
        return False
