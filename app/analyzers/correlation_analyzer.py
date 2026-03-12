def correlate_security_findings(
    nmap_hosts: list[dict],
    nmap_analysis: dict,
    pcap_events: list[dict],
    pcap_analysis: dict,
    syslog_events: list[dict],
    syslog_analysis: dict,
) -> dict:
    findings = []
    score = 0

    # Kumpulkan port terbuka dari Nmap
    open_ports = set()
    for host in nmap_hosts:
        for port in host.get("ports", []):
            open_ports.add(port.get("port"))

    # Ambil data PCAP
    pcap_top_ports = dict(pcap_analysis.get("top_ports", []))
    pcap_findings = pcap_analysis.get("findings", [])

    # Ambil data Syslog
    syslog_findings = syslog_analysis.get("findings", [])
    failed_by_ip = dict(syslog_analysis.get("failed_by_ip", []))
    success_by_ip = dict(syslog_analysis.get("success_by_ip", []))
    invalid_user_by_ip = dict(syslog_analysis.get("invalid_user_by_ip", []))

    # =========================
    # 1. SSH Brute Force
    # =========================
    ssh_open = 22 in open_ports
    ssh_traffic = pcap_top_ports.get(22, 0)
    auth_fail_total = sum(failed_by_ip.values())
    auth_success_total = sum(success_by_ip.values())

    ssh_evidence = []

    if ssh_open:
        ssh_evidence.append("Port 22 terbuka pada hasil Nmap.")
    if ssh_traffic >= 20:
        ssh_evidence.append(f"Terdapat {ssh_traffic} koneksi ke port 22 pada PCAP.")
    if auth_fail_total >= 5:
        ssh_evidence.append(f"Terdapat {auth_fail_total} login gagal pada syslog.")
    if auth_success_total >= 1 and auth_fail_total >= 5:
        ssh_evidence.append(
            f"Terdapat pola auth mencurigakan: {auth_fail_total} gagal dan {auth_success_total} sukses."
        )

    if ssh_open and ssh_traffic >= 20 and auth_fail_total >= 5:
        severity = "Critical" if auth_success_total >= 1 else "High"
        findings.append({
            "type": "possible_ssh_brute_force",
            "severity": severity,
            "title": "Possible SSH Brute Force Attack",
            "evidence": ssh_evidence,
        })
        score += 8 if severity == "Critical" else 6

    # =========================
    # 2. Invalid User Enumeration
    # =========================
    invalid_total = sum(invalid_user_by_ip.values())
    if invalid_total >= 3:
        evidence = [
            f"Terdapat {invalid_total} percobaan invalid user pada syslog."
        ]

        if ssh_open:
            evidence.append("Port 22 terbuka pada hasil Nmap.")

        findings.append({
            "type": "possible_user_enumeration",
            "severity": "High" if invalid_total >= 5 else "Medium",
            "title": "Possible Invalid User Enumeration",
            "evidence": evidence,
        })
        score += 4 if invalid_total >= 5 else 2

    # =========================
    # 3. SMB Exposure + Traffic
    # =========================
    smb_open = 445 in open_ports
    smb_traffic = pcap_top_ports.get(445, 0)

    if smb_open and smb_traffic >= 10:
        findings.append({
            "type": "smb_exposure_with_activity",
            "severity": "High",
            "title": "SMB Exposure With Active Traffic",
            "evidence": [
                "Port 445 terbuka pada hasil Nmap.",
                f"Terdapat {smb_traffic} koneksi ke port 445 pada PCAP.",
            ],
        })
        score += 4
    elif smb_open:
        findings.append({
            "type": "smb_exposure",
            "severity": "Medium",
            "title": "SMB Exposure Detected",
            "evidence": [
                "Port 445 terbuka pada hasil Nmap.",
            ],
        })
        score += 2

    # =========================
    # 4. RDP Exposure + Traffic
    # =========================
    rdp_open = 3389 in open_ports
    rdp_traffic = pcap_top_ports.get(3389, 0)

    if rdp_open and rdp_traffic >= 10:
        findings.append({
            "type": "rdp_exposure_with_activity",
            "severity": "High",
            "title": "RDP Exposure With Active Traffic",
            "evidence": [
                "Port 3389 terbuka pada hasil Nmap.",
                f"Terdapat {rdp_traffic} koneksi ke port 3389 pada PCAP.",
            ],
        })
        score += 4
    elif rdp_open:
        findings.append({
            "type": "rdp_exposure",
            "severity": "Medium",
            "title": "RDP Exposure Detected",
            "evidence": [
                "Port 3389 terbuka pada hasil Nmap.",
            ],
        })
        score += 2

    # =========================
    # 5. Lateral Movement Style
    # =========================
    pcap_lateral = [
        f for f in pcap_findings
        if "lateral movement" in f.lower() or "internal spread" in f.lower()
    ]
    if pcap_lateral:
        findings.append({
            "type": "possible_lateral_movement",
            "severity": "High",
            "title": "Possible Lateral Movement Activity",
            "evidence": pcap_lateral[:3],
        })
        score += 5

    # =========================
    # 6. General Auth Abuse
    # =========================
    suspicious_auth = [
        f for f in syslog_findings
        if "suspicious auth" in f.lower()
        or "brute force" in f.lower()
        or "enumeration" in f.lower()
    ]
    if suspicious_auth and not any(f["type"] == "possible_ssh_brute_force" for f in findings):
        findings.append({
            "type": "auth_abuse_detected",
            "severity": "High",
            "title": "Authentication Abuse Detected",
            "evidence": suspicious_auth[:3],
        })
        score += 4

    overall_severity = "Low"
    if score >= 10:
        overall_severity = "Critical"
    elif score >= 6:
        overall_severity = "High"
    elif score >= 3:
        overall_severity = "Medium"

    risk_label = "Informational"
    if score >= 10:
        risk_label = "Immediate Action"
    elif score >= 6:
        risk_label = "Priority Review"
    elif score >= 3:
        risk_label = "Monitor"

    return {
        "score": score,
        "severity": overall_severity,
        "risk_label": risk_label,
        "findings": findings,
    }