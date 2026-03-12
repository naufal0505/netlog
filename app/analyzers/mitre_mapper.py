MITRE_MAP = {
    "port_scan": {
        "technique": "T1046",
        "name": "Network Service Scanning"
    },
    "ssh_bruteforce": {
        "technique": "T1110",
        "name": "Brute Force"
    },
    "lateral_movement": {
        "technique": "T1021",
        "name": "Remote Services"
    },
    "beaconing_pattern": {
        "technique": "T1071",
        "name": "Application Layer Protocol"
    },
    "dns_anomaly": {
        "technique": "T1071.004",
        "name": "DNS C2 Channel"
    }
}


def map_mitre(findings):

    mitre_hits = []

    for finding in findings:

        t = finding.get("type")

        if t in MITRE_MAP:

            mitre = MITRE_MAP[t]

            mitre_hits.append({
                "technique": mitre["technique"],
                "name": mitre["name"],
                "evidence": finding["message"]
            })

    return mitre_hits