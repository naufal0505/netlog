from collections import Counter, defaultdict


def analyze_syslog_events(events: list[dict]) -> dict:
    counter = Counter()
    failed_by_ip = Counter()
    invalid_user_by_ip = Counter()
    success_by_ip = Counter()
    sudo_by_user = Counter()
    firewall_by_ip = Counter()
    privilege_by_ip = Counter()
    user_creation_count = 0

    findings = []
    score = 0

    # kumpulkan statistik dasar
    for event in events:
        event_type = event.get("event_type", "other")
        counter[event_type] += 1

        data = event.get("data", {})
        src_ip = data.get("src_ip", "unknown")
        username = data.get("username")

        if event_type == "auth_failure" and src_ip != "unknown":
            failed_by_ip[src_ip] += 1

        elif event_type == "invalid_user" and src_ip != "unknown":
            invalid_user_by_ip[src_ip] += 1

        elif event_type == "auth_success" and src_ip != "unknown":
            success_by_ip[src_ip] += 1

        elif event_type == "sudo_session" and username:
            sudo_by_user[username] += 1

        elif event_type == "firewall_block" and src_ip != "unknown":
            firewall_by_ip[src_ip] += 1

        elif event_type == "privilege_escalation" and src_ip != "unknown":
            privilege_by_ip[src_ip] += 1

        elif event_type == "user_creation":
            user_creation_count += 1

    failed_count = counter.get("auth_failure", 0)
    invalid_user_count = counter.get("invalid_user", 0)
    success_count = counter.get("auth_success", 0)
    sudo_count = counter.get("sudo_session", 0)
    firewall_count = counter.get("firewall_block", 0)
    privilege_count = counter.get("privilege_escalation", 0)

    # 1. auth failure global
    if failed_count >= 20:
        findings.append(
            f"Brute force pattern: terdapat {failed_count} percobaan login gagal."
        )
        score += 5
    elif failed_count >= 5:
        findings.append(
            f"Terdapat {failed_count} percobaan login gagal (auth_failure)."
        )
        score += 3

    # 2. invalid user global
    if invalid_user_count >= 10:
        findings.append(
            f"User enumeration pattern: terdapat {invalid_user_count} percobaan user tidak valid."
        )
        score += 4
    elif invalid_user_count >= 3:
        findings.append(
            f"Terdapat {invalid_user_count} percobaan user tidak valid."
        )
        score += 2

    # 3. auth failure per IP
    for ip, count in failed_by_ip.most_common(10):
        if count >= 10:
            findings.append(
                f"Possible brute force dari IP {ip}: {count} login gagal."
            )
            score += 4
        elif count >= 5:
            findings.append(
                f"Suspicious auth activity dari IP {ip}: {count} login gagal."
            )
            score += 2

    # 4. invalid user per IP
    for ip, count in invalid_user_by_ip.most_common(10):
        if count >= 5:
            findings.append(
                f"Possible user enumeration dari IP {ip}: {count} percobaan invalid user."
            )
            score += 3

    # 5. login sukses setelah banyak gagal
    suspicious_auth_detected = False
    for ip, success in success_by_ip.items():
        fail = failed_by_ip.get(ip, 0)
        if fail >= 3 and success >= 1:
            findings.append(
                f"Suspicious auth pattern dari IP {ip}: {fail} login gagal diikuti {success} login sukses."
            )
            score += 5
            suspicious_auth_detected = True

    # 6. sudo activity
    if sudo_count >= 20:
        findings.append(
            f"Terdapat aktivitas sudo tinggi: {sudo_count} session."
        )
        score += 3
    elif sudo_count >= 5:
        findings.append(
            f"Terdapat beberapa aktivitas sudo: {sudo_count} session."
        )
        score += 1

    for user, count in sudo_by_user.most_common(5):
        if count >= 10:
            findings.append(
                f"User {user} memiliki aktivitas sudo tinggi: {count} session."
            )
            score += 2

    # 7. firewall block
    if firewall_count >= 20:
        findings.append(
            f"Terdapat {firewall_count} firewall block events."
        )
        score += 2
    elif firewall_count >= 5:
        findings.append(
            f"Terdapat beberapa firewall block events: {firewall_count}."
        )
        score += 1

    for ip, count in firewall_by_ip.most_common(5):
        if count >= 10:
            findings.append(
                f"IP {ip} sering diblokir firewall: {count} kali."
            )
            score += 2

    # 8. privilege escalation / su
    if privilege_count >= 5:
        findings.append(
            f"Terdapat indikasi privilege escalation / su activity: {privilege_count} event."
        )
        score += 3

    for ip, count in privilege_by_ip.most_common(5):
        if count >= 3:
            findings.append(
                f"IP {ip} terkait aktivitas privilege escalation sebanyak {count} event."
            )
            score += 2

    # 9. user creation
    if user_creation_count >= 1:
        findings.append(
            f"Terdapat aktivitas pembuatan user baru: {user_creation_count} event."
        )
        score += 3

    severity = "Low"
    if score >= 10:
        severity = "High"
    elif score >= 4:
        severity = "Medium"

    risk_label = "Informational"
    if score >= 10:
        risk_label = "Priority Review"
    elif score >= 4:
        risk_label = "Monitor"

    return {
        "event_counts": dict(counter),
        "failed_by_ip": failed_by_ip.most_common(10),
        "invalid_user_by_ip": invalid_user_by_ip.most_common(10),
        "success_by_ip": success_by_ip.most_common(10),
        "score": score,
        "severity": severity,
        "risk_label": risk_label,
        "findings": findings,
    }