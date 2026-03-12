def classify_nmap_threat(analysis: dict) -> dict:
    top_hosts = analysis.get("host_scores", [])
    top_host = top_hosts[0] if top_hosts else None

    if not top_host:
        return {
            "category": "Exposure",
            "label": "No Exposure Data",
            "overall_risk": "LOW",
            "reason": "Tidak ada host aktif atau port terbuka yang terdeteksi pada hasil pemindaian.",
        }

    severity = str(top_host.get("severity", "Low")).lower()
    score = top_host.get("score", 0)
    findings = [str(x).lower() for x in top_host.get("findings", [])]
    open_ports = top_host.get("open_ports", 0)

    if any("rdp" in f or "smb" in f or "telnet" in f or "redis" in f for f in findings):
        return {
            "category": "Exposure",
            "label": "Sensitive Service Exposure",
            "overall_risk": "HIGH",
            "reason": (
                "Terdapat service sensitif yang terbuka ke jaringan, seperti remote access atau database service, "
                "yang berpotensi meningkatkan permukaan serangan jika tidak dibatasi dengan benar."
            ),
        }

    if severity == "critical" or score >= 6:
        return {
            "category": "Exposure",
            "label": "High Risk Exposure",
            "overall_risk": "HIGH",
            "reason": (
                f"Host dengan risiko tertinggi memiliki skor {score} dengan {open_ports} port terbuka, "
                "menunjukkan eksposur service yang perlu segera divalidasi dan dibatasi."
            ),
        }

    if severity == "high" or score >= 4:
        return {
            "category": "Exposure",
            "label": "Moderate Risk Exposure",
            "overall_risk": "MEDIUM",
            "reason": (
                f"Terdapat host dengan beberapa service terbuka dan skor risiko {score}, "
                "sehingga perlu peninjauan terhadap akses, kebutuhan service, dan pembatasan jaringan."
            ),
        }

    return {
        "category": "Exposure",
        "label": "Low Exposure",
        "overall_risk": "LOW",
        "reason": (
            f"Terdapat eksposur jaringan tingkat rendah dengan {open_ports} port terbuka pada host berisiko tertinggi, "
            "namun belum terlihat service dengan indikasi risiko dominan."
        ),
    }


def classify_pcap_threat(analysis: dict) -> dict:
    findings = analysis.get("findings", [])
    score = analysis.get("score", 0)

    top_ports = dict(analysis.get("top_ports", []))
    top_destinations = dict(analysis.get("top_destinations", []))

    finding_types = [f.get("type", "") for f in findings]
    counts = {}
    for ftype in finding_types:
        counts[ftype] = counts.get(ftype, 0) + 1

    def has(ftype: str) -> bool:
        return counts.get(ftype, 0) > 0

    mdns = top_ports.get(5353, 0)
    llmnr = top_ports.get(5355, 0)
    ssdp = top_ports.get(1900, 0)
    netbios = top_ports.get(137, 0) + top_ports.get(138, 0) + top_ports.get(139, 0)

    mdns_dst = top_destinations.get("224.0.0.251", 0)
    llmnr_dst = top_destinations.get("224.0.0.252", 0)
    ssdp_dst = top_destinations.get("239.255.255.250", 0)

    if has("ssh_bruteforce"):
        return {
            "category": "Credential Attack",
            "label": "Possible SSH Brute Force",
            "overall_risk": "HIGH",
            "reason": (
                "Terdapat koneksi SSH berulang dalam jumlah tinggi ke target yang sama, "
                "yang mengindikasikan kemungkinan brute force terhadap layanan SSH."
            ),
        }

    if has("beaconing_pattern"):
        return {
            "category": "Command and Control",
            "label": "Possible Beaconing",
            "overall_risk": "HIGH",
            "reason": (
                "Ditemukan pola koneksi periodik dengan interval yang stabil dari host yang sama ke tujuan yang sama, "
                "yang mengarah pada kemungkinan beaconing atau komunikasi command-and-control."
            ),
        }

    if has("dns_anomaly"):
        return {
            "category": "DNS Abuse",
            "label": "Suspicious DNS Activity",
            "overall_risk": "HIGH" if score >= 12 else "MEDIUM",
            "reason": (
                "Ditemukan anomali DNS seperti volume query tinggi, rasio NXDOMAIN tinggi, domain unik berlebihan, "
                "atau domain ber-entropy tinggi yang dapat mengindikasikan DGA, DNS tunneling, atau aktivitas malware."
            ),
        }

    if has("port_scan"):
        return {
            "category": "Reconnaissance",
            "label": "Possible Port Scanning",
            "overall_risk": "HIGH" if score >= 12 else "MEDIUM",
            "reason": (
                "Ditemukan sumber yang mengakses banyak port berbeda, yang merupakan pola umum reconnaissance "
                "atau percobaan pemetaan layanan pada host target."
            ),
        }

    if has("lateral_movement"):
        return {
            "category": "Internal Threat Activity",
            "label": "Possible Lateral Movement",
            "overall_risk": "HIGH",
            "reason": (
                "Ditemukan host yang berkomunikasi dengan banyak host internal lain melalui koneksi TCP, "
                "yang dapat mengindikasikan percobaan penyebaran atau lateral movement di jaringan internal."
            ),
        }

    if has("suspicious_external_host"):
        return {
            "category": "External Communication",
            "label": "Suspicious External Host",
            "overall_risk": "MEDIUM",
            "reason": (
                "Ditemukan komunikasi berulang ke host eksternal yang diakses oleh banyak host internal "
                "atau melibatkan port yang tidak umum, sehingga perlu divalidasi apakah merupakan layanan sah "
                "atau infrastruktur yang mencurigakan."
            ),
        }

    if has("network_health"):
        return {
            "category": "Network Health",
            "label": "Possible Packet Loss / Network Instability",
            "overall_risk": "MEDIUM" if score >= 5 else "LOW",
            "reason": (
                "Ditemukan indikator kualitas jaringan seperti TCP retransmission, duplicate ACK, atau out-of-order segment "
                "yang dapat mengarah pada packet loss atau ketidakstabilan koneksi."
            ),
        }

    if has("external_connection"):
        return {
            "category": "External Communication",
            "label": "Repeated External Connection",
            "overall_risk": "MEDIUM" if score >= 5 else "LOW",
            "reason": (
                "Ditemukan koneksi berulang ke host eksternal publik, sehingga perlu dipastikan apakah komunikasi tersebut "
                "sesuai dengan kebutuhan layanan yang memang digunakan di lingkungan ini."
            ),
        }

    if has("ssh_suspicious") or has("ssh_activity"):
        return {
            "category": "Remote Access Activity",
            "label": "Elevated SSH Activity",
            "overall_risk": "MEDIUM",
            "reason": (
                "Terlihat aktivitas SSH dalam volume yang cukup tinggi, yang dapat berkaitan dengan administrasi rutin "
                "atau percobaan autentikasi berulang dan perlu diverifikasi konteksnya."
            ),
        }

    if has("sensitive_port_activity"):
        return {
            "category": "Sensitive Service Exposure",
            "label": "Sensitive Port Activity",
            "overall_risk": "MEDIUM",
            "reason": (
                "Ditemukan aktivitas signifikan menuju port sensitif seperti SSH, SMB, RDP, database, "
                "atau layanan remote access lainnya yang perlu ditinjau sesuai konteks jaringan."
            ),
        }

    if (
        has("broadcast_traffic")
        or has("local_lan_traffic")
        or has("common_service_activity")
        or has("high_port_volume")
    ):
        reasons = []
        if mdns >= 100 or mdns_dst >= 100:
            reasons.append(f"mDNS/224.0.0.251 ({max(mdns, mdns_dst)} event)")
        if llmnr >= 50 or llmnr_dst >= 50:
            reasons.append(f"LLMNR/224.0.0.252 ({max(llmnr, llmnr_dst)} event)")
        if ssdp >= 50 or ssdp_dst >= 50:
            reasons.append(f"SSDP/239.255.255.250 ({max(ssdp, ssdp_dst)} event)")
        if netbios >= 100:
            reasons.append(f"NetBIOS ({netbios} event)")

        detail = ", ".join(reasons) if reasons else "broadcast, multicast, atau service discovery internal"

        return {
            "category": "Network Service Discovery",
            "label": "Service Discovery / Broadcast Dominant Traffic",
            "overall_risk": "LOW" if score < 5 else "MEDIUM",
            "reason": (
                f"Traffic didominasi oleh aktivitas {detail}, yang umumnya berkaitan dengan service discovery "
                "dan komunikasi lokal di LAN. Pola ini sering normal, namun tetap perlu divalidasi bila volumenya "
                "lebih tinggi dari baseline jaringan."
            ),
        }

    return {
        "category": "Network Behavior",
        "label": "Unclassified Suspicious Pattern" if score >= 5 else "Mostly Normal",
        "overall_risk": "MEDIUM" if score >= 5 else "LOW",
        "reason": (
            "Ditemukan pola komunikasi jaringan yang belum cukup kuat untuk dipetakan ke skenario ancaman tertentu, "
            "namun tetap layak ditinjau sesuai konteks lingkungan."
            if score >= 5
            else "Traffic didominasi pola komunikasi umum dan belum menunjukkan indikasi ancaman yang kuat."
        ),
    }


def classify_syslog_threat(analysis: dict) -> dict:
    findings = [str(x).lower() for x in analysis.get("findings", [])]
    findings_text = " ".join(findings)
    score = analysis.get("score", 0)

    if "suspicious auth" in findings_text:
        return {
            "category": "Authentication",
            "label": "Suspicious Auth Pattern",
            "overall_risk": "HIGH",
            "reason": (
                "Ditemukan pola login gagal berulang yang diikuti login sukses dari sumber yang sama, "
                "yang dapat mengindikasikan password guessing atau autentikasi mencurigakan."
            ),
        }

    if "brute force" in findings_text:
        return {
            "category": "Authentication",
            "label": "Brute Force Pattern",
            "overall_risk": "HIGH",
            "reason": (
                "Ditemukan banyak percobaan autentikasi gagal dalam volume tinggi, "
                "yang konsisten dengan indikasi brute force pada layanan login."
            ),
        }

    if "enumeration" in findings_text:
        return {
            "category": "Authentication",
            "label": "User Enumeration Pattern",
            "overall_risk": "MEDIUM",
            "reason": (
                "Ditemukan percobaan akses terhadap banyak username yang tidak valid, "
                "yang mengarah pada upaya enumerasi akun sebelum serangan lanjutan."
            ),
        }

    if "sudo" in findings_text or "privilege" in findings_text:
        return {
            "category": "Privilege Activity",
            "label": "Suspicious Privilege Usage",
            "overall_risk": "MEDIUM" if score < 8 else "HIGH",
            "reason": (
                "Terdapat indikasi penggunaan hak akses istimewa atau aktivitas privilege escalation "
                "yang perlu diverifikasi terhadap aktivitas administratif yang sah."
            ),
        }

    if score >= 4:
        return {
            "category": "Authentication",
            "label": "Suspicious Login Activity",
            "overall_risk": "MEDIUM",
            "reason": (
                "Terdapat aktivitas autentikasi yang tidak normal berdasarkan volume event, "
                "meskipun belum cukup spesifik untuk dikategorikan sebagai brute force atau suspicious auth pattern."
            ),
        }

    return {
        "category": "Authentication",
        "label": "Mostly Normal",
        "overall_risk": "LOW",
        "reason": "Tidak ditemukan pola autentikasi berbahaya yang kuat pada system log.",
    }