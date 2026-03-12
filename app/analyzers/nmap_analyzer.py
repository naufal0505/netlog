from collections import Counter


INTERESTING_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    69: "TFTP",
    80: "HTTP",
    111: "RPCbind",
    135: "MSRPC",
    139: "NetBIOS",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP",
    5900: "VNC",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    5080: "Web-Alt",
}

SENSITIVE_PORT_WEIGHTS = {
    22: 1,
    23: 3,
    139: 2,
    445: 3,
    3389: 3,
    5900: 2,
    3306: 2,
    5432: 2,
    6379: 3,
}

SENSITIVE_SERVICES = {
    "redis",
    "mysql",
    "postgresql",
    "mongodb",
    "telnet",
    "ms-wbt-server",
    "microsoft-ds",
}


def get_severity(score: int) -> str:
    if score >= 8:
        return "Critical"
    if score >= 5:
        return "High"
    if score >= 2:
        return "Medium"
    return "Low"


def get_risk_label(score: int) -> str:
    if score >= 8:
        return "Immediate Review"
    if score >= 5:
        return "Priority Check"
    if score >= 2:
        return "Monitor"
    return "Informational"


def analyze_nmap_hosts(hosts: list[dict]) -> dict:
    up_hosts = [host for host in hosts if host.get("status", "up") == "up"]

    total_hosts = len(up_hosts)
    total_open_ports = sum(len(host["ports"]) for host in up_hosts)

    service_counter = Counter()
    interesting_findings = []
    host_scores = []

    for host in hosts:
        score = 0
        host_findings = []

        ip = host["ip"]
        is_localhost = ip in ("127.0.0.1", "::1", "localhost")
        is_up = host.get("status", "up") == "up"
        open_ports = host.get("ports", [])

        if not is_up:
            host_scores.append({
                "ip": f"{ip} [host down]",
                "open_ports": 0,
                "score": 0,
                "severity": "Low",
                "risk_label": "Informational"
            })
            continue

        port_numbers = {p["port"] for p in open_ports}
        service_names = {p["service"].lower() for p in open_ports}

        for port in open_ports:
            service_counter[port["service"]] += 1

            port_num = port["port"]
            service_name = port["service"].lower()

            if port_num in INTERESTING_PORTS:
                score += 1
                host_findings.append(
                    f"Port {port_num} terbuka ({INTERESTING_PORTS[port_num]})"
                )

            if port_num in SENSITIVE_PORT_WEIGHTS:
                extra_weight = SENSITIVE_PORT_WEIGHTS[port_num]
                score += extra_weight
                host_findings.append(
                    f"Port sensitif terdeteksi: {port_num}/{port['protocol']} "
                    f"(risk score +{extra_weight})"
                )

            if port_num >= 1024 and port_num not in {8080, 8443, 5080}:
                score += 1
                host_findings.append(
                    f"Port tinggi terbuka: {port_num}/{port['protocol']}"
                )

            if service_name in SENSITIVE_SERVICES:
                score += 2
                host_findings.append(
                    f"Service sensitif terdeteksi: {port['service']}"
                )

        if 139 in port_numbers and 445 in port_numbers:
            score += 2
            host_findings.append(
                "Kombinasi NetBIOS/SMB terdeteksi (139 + 445), berpotensi untuk enumerasi atau file-sharing exposure."
            )

        if 23 in port_numbers:
            score += 1
            host_findings.append(
                "Telnet terdeteksi; protokol ini tidak terenkripsi dan berisiko tinggi."
            )

        if 22 in port_numbers:
            host_findings.append(
                "SSH terbuka; pastikan akses dibatasi dan autentikasi kuat digunakan."
            )

        if 80 in port_numbers or 443 in port_numbers or 5080 in port_numbers or 8080 in port_numbers:
            host_findings.append(
                "Service web terdeteksi; validasi apakah endpoint memang perlu diekspos."
            )

        if 3389 in port_numbers:
            score += 1
            host_findings.append(
                "RDP terbuka; pastikan akses dibatasi dan dipantau."
            )

        if 3306 in port_numbers or 5432 in port_numbers or 6379 in port_numbers:
            score += 2
            host_findings.append(
                "Port database/service internal terdeteksi terbuka; validasi apakah memang perlu diekspos."
            )

        if len(open_ports) >= 5:
            score += 2
            host_findings.append(
                f"Host memiliki banyak port terbuka ({len(open_ports)} port)"
            )
        elif len(open_ports) >= 3:
            score += 1
            host_findings.append(
                f"Host memiliki beberapa port terbuka ({len(open_ports)} port)"
            )

        if is_localhost:
            host_findings.append(
                "Host merupakan localhost; exposure hanya relevan jika service dapat diakses dari jaringan lain."
            )

        severity = get_severity(score)
        risk_label = get_risk_label(score)

        if host_findings:
            interesting_findings.append({
                "ip": ip,
                "score": score,
                "severity": severity,
                "risk_label": risk_label,
                "findings": host_findings
            })

        host_scores.append({
            "ip": ip,
            "open_ports": len(open_ports),
            "score": score,
            "severity": severity,
            "risk_label": risk_label
        })

    host_scores.sort(
        key=lambda x: (x["score"], x["open_ports"]),
        reverse=True
    )
    top_services = service_counter.most_common(10)

    return {
        "total_hosts": total_hosts,
        "total_open_ports": total_open_ports,
        "top_services": top_services,
        "interesting_findings": interesting_findings,
        "host_scores": host_scores,
    }