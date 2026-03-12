def generate_executive_summary(report: dict) -> str:
    analysis = report["analysis"]
    hosts = report["hosts"]

    total_hosts = analysis.get("total_hosts", 0)
    total_ports = analysis.get("total_open_ports", 0)
    host_scores = analysis.get("host_scores", [])
    top_risk = host_scores[0] if host_scores else None

    up_hosts = [host for host in hosts if host.get("status", "up") == "up"]
    down_hosts = [host for host in hosts if host.get("status", "up") != "up"]

    lines = []
    lines.append("Executive Summary")
    lines.append("-----------------")
    lines.append(
        f"Teridentifikasi {total_hosts} host aktif dengan total {total_ports} port terbuka."
    )

    if down_hosts:
        lines.append(
            f"Sebanyak {len(down_hosts)} host tambahan terdeteksi dalam keadaan down/tidak responsif."
        )

    if top_risk and top_risk.get("score", 0) > 0:
        lines.append(
            f"Host dengan prioritas pemeriksaan tertinggi adalah {top_risk['ip']} "
            f"dengan skor risiko {top_risk['score']} dan {top_risk['open_ports']} port terbuka."
        )

    findings = analysis.get("interesting_findings", [])
    if findings:
        lines.append("Temuan utama:")
        for item in findings[:3]:
            lines.append(f"- Host {item['ip']}:")
            for finding in item["findings"][:3]:
                lines.append(f"  • {finding}")

    recommendations = []
    observed_ports = set()

    for host in up_hosts:
        for port in host.get("ports", []):
            port_num = port["port"]
            observed_ports.add(port_num)

            if port_num == 445:
                recommendations.append(
                    "Verifikasi apakah SMB (445) memang perlu diekspos dan batasi akses hanya ke subnet yang diperlukan."
                )

            elif port_num == 139:
                recommendations.append(
                    "Validasi kebutuhan NetBIOS (139); nonaktifkan jika tidak diperlukan."
                )

            elif port_num == 135:
                recommendations.append(
                    "Pastikan akses ke MSRPC (135) dibatasi hanya untuk kebutuhan internal."
                )

            elif port_num == 23:
                recommendations.append(
                    "Segera evaluasi penggunaan Telnet (23); pertimbangkan migrasi ke SSH karena Telnet tidak terenkripsi."
                )

            elif port_num == 22:
                recommendations.append(
                    "Pastikan akses SSH (22) dibatasi, menggunakan autentikasi kuat, dan tidak terbuka ke jaringan yang tidak diperlukan."
                )

            elif port_num == 3389:
                recommendations.append(
                    "Batasi akses RDP (3389), gunakan segmentasi jaringan dan kontrol akses yang ketat."
                )

            elif port_num in {3306, 5432, 6379}:
                recommendations.append(
                    f"Pastikan service pada port {port_num} tidak diekspos tanpa kebutuhan yang jelas dan dilindungi autentikasi yang kuat."
                )

            elif port_num in {80, 443, 8080, 8443, 5080}:
                recommendations.append(
                    f"Periksa tujuan dan kebutuhan service web pada port {port_num}, serta pastikan patching dan kontrol akses memadai."
                )

    if 139 in observed_ports and 445 in observed_ports:
        recommendations.append(
            "Karena kombinasi 139 dan 445 terdeteksi, lakukan validasi risiko file-sharing exposure dan potensi enumerasi host internal."
        )

    if recommendations:
        lines.append("Rekomendasi awal:")
        seen = set()
        for rec in recommendations:
            if rec not in seen:
                lines.append(f"- {rec}")
                seen.add(rec)

    if total_hosts == 0 and total_ports == 0:
        lines.append(
            "Tidak ditemukan host aktif dengan port terbuka pada hasil scan ini."
        )

    return "\n".join(lines)