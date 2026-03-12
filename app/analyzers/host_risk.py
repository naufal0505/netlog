from collections import defaultdict


def calculate_host_risk(events, findings):

    host_scores = defaultdict(int)

    for event in events:

        src = event["data"].get("src_ip")
        dst = event["data"].get("dst_ip")

        if src:
            host_scores[src] += 1

        if dst:
            host_scores[dst] += 1

    for finding in findings:

        msg = finding.get("message", "")

        if "port scanning" in msg:
            for host in host_scores:
                host_scores[host] += 5

        if "beaconing" in msg:
            for host in host_scores:
                host_scores[host] += 8

        if "DNS anomaly" in msg:
            for host in host_scores:
                host_scores[host] += 6

    results = []

    for host, score in host_scores.items():

        risk = "LOW"

        if score >= 30:
            risk = "HIGH"
        elif score >= 10:
            risk = "MEDIUM"

        results.append({
            "host": host,
            "score": score,
            "risk": risk
        })

    results.sort(key=lambda x: x["score"], reverse=True)

    return results[:20]