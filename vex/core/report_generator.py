import json
from datetime import datetime


def generate_json_report(results, output_path):
    """Generate JSON report."""
    report = {
        "generated_at": datetime.now().isoformat(),
        "total_findings": len(results),
        "findings": results
    }
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)


def generate_markdown_report(results, output_path):
    """Generate Markdown report."""
    lines = []
    lines.append("# VEX Vulnerability Report")
    lines.append(f"Generated: {datetime.now().isoformat()}")
    lines.append(f"Total Findings: {len(results)}")
    lines.append("")

    if not results:
        lines.append("No vulnerabilities found.")
    else:
        for idx, finding in enumerate(results, 1):
            lines.append(f"## {idx}. {finding['type'].upper()}")
            lines.append(f"- **URL**: {finding['url']}")
            if 'param' in finding:
                lines.append(f"- **Parameter**: {finding['param']}")
            if 'payload' in finding:
                lines.append(f"- **Payload**: `{finding['payload']}`")
            lines.append(f"- **Confidence**: {finding['confidence']}")
            lines.append(f"- **Technique**: {finding.get('technique', 'N/A')}")
            if 'manual_test' in finding:
                lines.append(f"- **Manual Test**: {finding['manual_test']}")
            lines.append("")

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))


def generate_html_report(results, output_path):
    """Generate HTML report."""
    html = f"""<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VEX Vulnerability Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 1000px; margin: 0 auto; padding: 20px; }}
        h1 {{ color: #333; border-bottom: 2px solid #4CAF50; padding-bottom: 10px; }}
        .finding {{ border: 1px solid #ddd; border-left: 4px solid #4CAF50; padding: 15px; margin: 15px 0; border-radius: 4px; }}
        .finding.high {{ border-left-color: #f44336; }}
        .finding.medium {{ border-left-color: #ff9800; }}
        .finding.low {{ border-left-color: #4CAF50; }}
        .label {{ display: inline-block; padding: 3px 8px; border-radius: 3px; color: white; font-size: 0.8em; margin-right: 5px; }}
        .label.high {{ background-color: #f44336; }}
        .label.medium {{ background-color: #ff9800; }}
        .label.low {{ background-color: #4CAF50; }}
        pre {{ background: #f4f4f4; padding: 10px; border-radius: 4px; overflow-x: auto; }}
    </style>
</head>
<body>
    <h1>VEX Vulnerability Report</h1>
    <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    <p>Total Findings: {len(results)}</p>
    <hr>
"""
    if not results:
        html += "<p>No vulnerabilities found.</p>"
    else:
        for finding in results:
            confidence = finding.get('confidence', 'low')
            html += f'<div class="finding {confidence}">'
            html += f"<h3>{finding['type'].upper()} <span class='label {confidence}'>{confidence}</span></h3>"
            html += f"<p><strong>URL:</strong> <a href='{finding['url']}' target='_blank'>{finding['url']}</a></p>"
            if 'param' in finding:
                html += f"<p><strong>Parameter:</strong> {finding['param']}</p>"
            if 'payload' in finding:
                html += f"<p><strong>Payload:</strong><pre>{finding['payload']}</pre></p>"
            html += f"<p><strong>Technique:</strong> {finding.get('technique', 'N/A')}</p>"
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
