import json
from datetime import datetime


# CVSS v3.1 Base Score Calculator
CVSS_BASE_SCORES = {
    'sqli': {'av': 'N', 'ac': 'L', 'pr': 'N', 'ui': 'N', 's': 'U', 'c': 'H', 'i': 'H', 'a': 'N', 'base': 9.8},
    'xss': {'av': 'N', 'ac': 'L', 'pr': 'N', 'ui': 'R', 's': 'C', 'c': 'L', 'i': 'L', 'a': 'N', 'base': 6.1},
    'rce': {'av': 'N', 'ac': 'L', 'pr': 'N', 'ui': 'N', 's': 'U', 'c': 'H', 'i': 'H', 'a': 'H', 'base': 10.0},
    'ssrf': {'av': 'N', 'ac': 'L', 'pr': 'N', 'ui': 'R', 's': 'U', 'c': 'N', 'i': 'H', 'a': 'N', 'base': 8.6},
    'xxe': {'av': 'N', 'ac': 'L', 'pr': 'N', 'ui': 'R', 's': 'U', 'c': 'H', 'i': 'N', 'a': 'N', 'base': 7.5},
    'path_traversal': {'av': 'N', 'ac': 'L', 'pr': 'N', 'ui': 'R', 's': 'U', 'c': 'H', 'i': 'N', 'a': 'N', 'base': 7.5},
    'idor': {'av': 'N', 'ac': 'L', 'pr': 'N', 'ui': 'R', 's': 'U', 'c': 'H', 'i': 'H', 'a': 'N', 'base': 8.1},
    'bac': {'av': 'N', 'ac': 'L', 'pr': 'N', 'ui': 'R', 's': 'U', 'c': 'H', 'i': 'H', 'a': 'N', 'base': 8.1},
}

CONFIDENCE_MULTIPLIER = {
    'high': 1.0,
    'medium': 0.7,
    'low': 0.4,
}


def calculate_cvss(vuln_type, confidence):
    """CVSS v3.1 benzeri skor hesapla."""
    base = CVSS_BASE_SCORES.get(vuln_type, {}).get('base', 5.0)
    multiplier = CONFIDENCE_MULTIPLIER.get(confidence, 0.5)
    score = round(base * multiplier, 1)
    return min(score, 10.0)


def get_severity(score):
    """CVSS skoruna göre ciddiyet seviyesi."""
    if score >= 9.0:
        return 'CRITICAL'
    elif score >= 7.0:
        return 'HIGH'
    elif score >= 4.0:
        return 'MEDIUM'
    elif score > 0:
        return 'LOW'
    return 'INFO'


def generate_poc(finding):
    """Bulgu için PoC (Proof of Concept) komutu üret."""
    poc_type = finding.get('type', '')
    url = finding.get('url', '')
    param = finding.get('param', '')
    payload = finding.get('payload', '')

    poc_commands = {
        'sqli': f'sqlmap -u "{url}" -p {param} --batch --level=3 --risk=2',
        'xss': f'dalfox url "{url}" -p {param} --blind-callback YOUR_SERVER',
        'rce': f'commix -u "{url}" --data="{param}=*"',
        'ssrf': f'SSRFmap -r request.txt -p {param} -m portscan',
        'xxe': f'Use Burp Repeater with: {payload[:80]}...' if payload else 'Use Burp Repeater with XXE payload',
        'path_traversal': f'dotdotpwn -m http -u "{url}" -q',
        'idor': f'Test with different session cookies on: {url}',
        'bac': f'curl -X GET "{url}" with different auth headers',
    }

    return poc_commands.get(poc_type, f'Manual test required for {poc_type}')


def generate_json_report(results, output_path):
    """Generate enhanced JSON report with CVSS scores and PoC."""
    findings = []
    for r in results:
        finding = dict(r)
        finding['cvss_score'] = calculate_cvss(r.get('type', ''), r.get('confidence', 'low'))
        finding['severity'] = get_severity(finding['cvss_score'])
        finding['poc_command'] = generate_poc(r)
        findings.append(finding)

    report = {
        "generated_at": datetime.now().isoformat(),
        "tool": "VEX - Vulnerability Explorer",
        "version": "0.5.0",
        "total_findings": len(findings),
        "summary": _generate_summary(findings),
        "findings": findings
    }
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)


def _generate_summary(findings):
    """Özet istatistikler üret."""
    summary = {
        "critical": 0, "high": 0, "medium": 0, "low": 0,
        "by_type": {}, "by_technique": {},
    }
    for f in findings:
        severity = f.get('severity', 'LOW')
        if severity == 'CRITICAL':
            summary['critical'] += 1
        elif severity == 'HIGH':
            summary['high'] += 1
        elif severity == 'MEDIUM':
            summary['medium'] += 1
        else:
            summary['low'] += 1

        vtype = f.get('type', 'unknown')
        summary['by_type'][vtype] = summary['by_type'].get(vtype, 0) + 1

        tech = f.get('technique', 'unknown')
        summary['by_technique'][tech] = summary['by_technique'].get(tech, 0) + 1

    return summary


def generate_markdown_report(results, output_path):
    """Generate enhanced Markdown report with CVSS and PoC."""
    lines = []
    lines.append("# VEX Vulnerability Report")
    lines.append(f"Generated: {datetime.now().isoformat()}")
    lines.append(f"Tool: VEX v0.5.0")
    lines.append(f"Total Findings: {len(results)}")
    lines.append("")

    # Summary
    summary = _generate_summary(results)
    lines.append("## Summary")
    lines.append(f"- Critical: {summary['critical']}")
    lines.append(f"- High: {summary['high']}")
    lines.append(f"- Medium: {summary['medium']}")
    lines.append(f"- Low: {summary['low']}")
    lines.append("")

    if not results:
        lines.append("No vulnerabilities found.")
    else:
        for idx, finding in enumerate(results, 1):
            cvss = calculate_cvss(finding.get('type', ''), finding.get('confidence', 'low'))
            severity = get_severity(cvss)
            poc = generate_poc(finding)

            lines.append(f"## {idx}. {finding['type'].upper()} [{severity}] (CVSS: {cvss})")
            lines.append(f"- **URL**: {finding['url']}")
            if 'param' in finding:
                lines.append(f"- **Parameter**: {finding['param']}")
            if 'payload' in finding:
                lines.append(f"- **Payload**: `{finding['payload']}`")
            lines.append(f"- **Confidence**: {finding.get('confidence', 'N/A')}")
            lines.append(f"- **Technique**: {finding.get('technique', 'N/A')}")
            if 'detected_wafs' in finding and finding['detected_wafs']:
                lines.append(f"- **Detected WAFs**: {', '.join(finding['detected_wafs'])}")
            lines.append(f"- **PoC Command**: `{poc}`")
            if 'manual_test' in finding:
                lines.append(f"- **Manual Test**: {finding['manual_test']}")
            lines.append("")

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))


def generate_html_report(results, output_path):
    """Generate enhanced HTML report with CVSS, PoC, and interactive UI."""
    summary = _generate_summary(results)
    html = f"""<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VEX Vulnerability Report</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; background: #1a1a2e; color: #eee; }}
        h1 {{ color: #00d4ff; border-bottom: 2px solid #00d4ff; padding-bottom: 10px; font-size: 2em; }}
        h2 {{ color: #00d4ff; margin: 20px 0 10px 0; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 10px; margin: 20px 0; }}
        .stat {{ background: #16213e; padding: 15px; border-radius: 8px; text-align: center; border: 1px solid #0f3460; }}
        .stat.critical {{ border-color: #ff0040; }}
        .stat.high {{ border-color: #ff6b35; }}
        .stat.medium {{ border-color: #ffc107; }}
        .stat.low {{ border-color: #4caf50; }}
        .stat-number {{ font-size: 2em; font-weight: bold; }}
        .stat-label {{ font-size: 0.9em; color: #aaa; }}
        .finding {{ background: #16213e; border: 1px solid #0f3460; border-radius: 8px; padding: 20px; margin: 15px 0; }}
        .finding.critical {{ border-left: 4px solid #ff0040; }}
        .finding.high {{ border-left: 4px solid #ff6b35; }}
        .finding.medium {{ border-left: 4px solid #ffc107; }}
        .finding.low {{ border-left: 4px solid #4caf50; }}
        .badge {{ display: inline-block; padding: 3px 10px; border-radius: 12px; color: white; font-size: 0.8em; font-weight: bold; margin-right: 5px; }}
        .badge.critical {{ background: #ff0040; }}
        .badge.high {{ background: #ff6b35; }}
        .badge.medium {{ background: #ffc107; color: #333; }}
        .badge.low {{ background: #4caf50; }}
        .poc {{ background: #0d1117; padding: 12px; border-radius: 6px; font-family: 'Consolas', monospace; font-size: 0.9em; overflow-x: auto; margin: 10px 0; border: 1px solid #30363d; }}
        .poc-label {{ color: #00d4ff; font-weight: bold; margin-bottom: 5px; }}
        a {{ color: #00d4ff; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        pre {{ background: #0d1117; padding: 12px; border-radius: 6px; overflow-x: auto; border: 1px solid #30363d; }}
        .meta {{ color: #aaa; font-size: 0.9em; }}
    </style>
</head>
<body>
    <h1>VEX Vulnerability Report</h1>
    <p class="meta">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Tool: VEX v0.5.0</p>
    <p class="meta">Total Findings: {len(results)}</p>

    <div class="summary">
        <div class="stat critical"><div class="stat-number" style="color:#ff0040">{summary['critical']}</div><div class="stat-label">Critical</div></div>
        <div class="stat high"><div class="stat-number" style="color:#ff6b35">{summary['high']}</div><div class="stat-label">High</div></div>
        <div class="stat medium"><div class="stat-number" style="color:#ffc107">{summary['medium']}</div><div class="stat-label">Medium</div></div>
        <div class="stat low"><div class="stat-number" style="color:#4caf50">{summary['low']}</div><div class="stat-label">Low</div></div>
    </div>

    <h2>Findings</h2>
"""
    if not results:
        html += "<p>No vulnerabilities found.</p>"
    else:
        for finding in results:
            confidence = finding.get('confidence', 'low')
            cvss = calculate_cvss(finding.get('type', ''), confidence)
            severity = get_severity(cvss)
            poc = generate_poc(finding)
            severity_class = severity.lower()

            html += f'<div class="finding {severity_class}">'
            html += f"<h3>{finding['type'].upper()} <span class='badge {severity_class}'>{severity}</span> <span class='meta'>CVSS: {cvss}</span></h3>"
            html += f"<p><strong>URL:</strong> <a href='{finding['url']}' target='_blank'>{finding['url']}</a></p>"
            if 'param' in finding:
                html += f"<p><strong>Parameter:</strong> {finding['param']}</p>"
            if 'payload' in finding:
                html += f"<p><strong>Payload:</strong></p><pre>{finding['payload']}</pre>"
            html += f"<p><strong>Technique:</strong> {finding.get('technique', 'N/A')}</p>"
            if 'detected_wafs' in finding and finding['detected_wafs']:
                html += f"<p><strong>Detected WAFs:</strong> {', '.join(finding['detected_wafs'])}</p>"
            html += f'<div class="poc"><div class="poc-label">PoC Command:</div>{poc}</div>'
            if 'manual_test' in finding:
                html += f"<p><strong>Manual Test:</strong> {finding['manual_test']}</p>"
            html += "</div>"

    html += """
</body>
</html>
"""
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)


def save_report(results, output_path):
    """Save report in appropriate format based on file extension."""
    if output_path.endswith('.json'):
        generate_json_report(results, output_path)
    elif output_path.endswith('.md'):
        generate_markdown_report(results, output_path)
    elif output_path.endswith('.html'):
        generate_html_report(results, output_path)
    else:
        generate_markdown_report(results, output_path)
