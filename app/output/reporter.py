import json
from datetime import datetime


def save_json_report(scan_file, hosts, analysis, output_path):
    report = {
        "generated_at": datetime.now().isoformat(),
        "source_file": scan_file,
        "hosts": hosts,
        "analysis": analysis,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)