from collections import defaultdict


def generate_attack_timeline(events, findings):
    """
    Membuat timeline aktivitas berdasarkan timestamp event
    dan jenis temuan (scan, beaconing, dns anomaly, dll)
    """

    timeline = []

    for event in events:
        ts = event.get("data", {}).get("timestamp")
        src = event.get("data", {}).get("src_ip")
        dst = event.get("data", {}).get("dst_ip")
        proto = event.get("data", {}).get("protocol")

        if not ts:
            continue

        timeline.append({
            "timestamp": ts,
            "src": src,
            "dst": dst,
            "protocol": proto,
        })

    timeline.sort(key=lambda x: x["timestamp"] or 0)

    attack_steps = []

    for finding in findings:

        t = finding.get("type")

        if t == "port_scan":
            attack_steps.append({
                "phase": "Reconnaissance",
                "description": finding["message"]
            })

        elif t == "ssh_bruteforce":
            attack_steps.append({
                "phase": "Credential Access",
                "description": finding["message"]
            })

        elif t == "lateral_movement":
            attack_steps.append({
                "phase": "Lateral Movement",
                "description": finding["message"]
            })

        elif t == "beaconing_pattern":
            attack_steps.append({
                "phase": "Command and Control",
                "description": finding["message"]
            })

        elif t == "dns_anomaly":
            attack_steps.append({
                "phase": "Command and Control",
                "description": finding["message"]
            })

        elif t == "suspicious_external_host":
            attack_steps.append({
                "phase": "Exfiltration / C2",
                "description": finding["message"]
            })

    return {
        "timeline_events": timeline[:200],
        "attack_steps": attack_steps
    }