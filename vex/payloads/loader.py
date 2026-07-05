import json


def load_custom_payloads(file_path):
    """Load custom payloads from JSON or text file.
    
    Text file: one payload per line.
    JSON file: dict of {vuln_type: [payloads]}.
    """
    try:
        if file_path.endswith('.json'):
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        else:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                return {'all': lines}
    except Exception as e:
        print(f"[!] Error loading custom payloads: {e}")
        return {}
