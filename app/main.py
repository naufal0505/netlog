import json
import os
from datetime import datetime

from app.parsers.nmap_parser import parse_nmap_file
from app.parsers.pcap_parser import parse_pcap
from app.parsers.syslog_parser import parse_syslog

from app.analyzers.nmap_analyzer import analyze_nmap_hosts
from app.analyzers.pcap_analyzer import analyze_pcap_events
from app.analyzers.syslog_analyzer import analyze_syslog_events

from app.analyzers.summary_generator import generate_executive_summary
from app.output.reporter import save_json_report

from app.analyzers.threat_classifier import (
    classify_nmap_threat,
    classify_pcap_threat,
    classify_syslog_threat,
)

from app.analyzers.attack_timeline import generate_attack_timeline
from app.analyzers.host_risk import calculate_host_risk
from app.analyzers.mitre_mapper import map_mitre

from app.ui.banner import show_banner, show_startup_animation

from rich.console import Console

console = Console()


def print_banner():
    console.print("\n[bold white]=== NetLog Analyzer ===[/bold white]")
    console.print("[cyan]1.[/cyan] File Nmap")
    console.print("[cyan]2.[/cyan] File PCAP")
    console.print("[cyan]3.[/cyan] File Sistem Log Server")
    console.print("[red]0.[/red] Keluar")


def ask_file_path():
    return input("\nMasukkan path file: ").strip().strip('"')


def validate_file(file_path: str) -> bool:
    if not os.path.exists(file_path):
        console.print(f"[bold red][ERROR][/bold red] File tidak ditemukan: {file_path}")
        return False
    return True


def ensure_reports_dir():
    os.makedirs("reports", exist_ok=True)


def print_threat_classification(classification: dict):
    console.print("\n[bold white]Threat Classification:[/bold white]")
    console.print(f"  - Category    : {classification['category']}")
    console.print(f"  - Label       : {classification['label']}")
    console.print(f"  - Overall Risk: {classification['overall_risk']}")
    console.print(f"  - Reason      : {classification['reason']}")


def _json_serializer(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    return str(obj)


def save_analysis_json(
    source_file: str,
    parsed_data,
    analysis: dict,
    classification: dict,
    output_path: str,
    extra: dict | None = None,
):
    ensure_reports_dir()

    payload = {
        "source_file": source_file,
        "parsed_data": parsed_data,
        "analysis": analysis,
        "classification": classification,
    }

    if extra:
        payload.update(extra)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False, default=_json_serializer)


def handle_nmap():
    file_path = ask_file_path()

    if not validate_file(file_path):
        return

    console.print("\n[bold cyan][INFO][/bold cyan] Menganalisis file Nmap...\n")

    try:
        with console.status("[bold cyan]Parsing dan menganalisis Nmap...[/bold cyan]", spinner="dots"):
            hosts = parse_nmap_file(file_path)
            analysis = analyze_nmap_hosts(hosts)
            classification = classify_nmap_threat(analysis)
    except Exception as e:
        console.print(f"[bold red][ERROR][/bold red] Gagal membaca file Nmap: {e}")
        return

    console.print("[bold white]=== Scan Summary ===[/bold white]\n")

    if not hosts:
        console.print("Tidak ada host up / port open yang terbaca.")
        return

    console.print(f"Hosts up        : {analysis.get('total_hosts', 0)}")
    console.print(f"Total open ports: {analysis.get('total_open_ports', 0)}\n")

    console.print("[bold white]Top Services:[/bold white]")
    for service, count in analysis.get("top_services", []):
        console.print(f"  - {service}: {count}")

    console.print("\n[bold white]Host Details:[/bold white]")
    for host in hosts:
        console.print(f"Host: {host.get('ip', 'unknown')}")

        if not host.get("ports"):
            console.print("  Tidak ada port open")
        else:
            for port in host.get("ports", []):
                version_text = " ".join(
                    x for x in [port.get("product"), port.get("version")] if x
                ).strip()

                if version_text:
                    console.print(
                        f"  - {port.get('port')}/{port.get('protocol')} -> "
                        f"{port.get('service')} ({version_text})"
                    )
                else:
                    console.print(
                        f"  - {port.get('port')}/{port.get('protocol')} -> "
                        f"{port.get('service')}"
                    )
        console.print()

    console.print("[bold white]Interesting Findings:[/bold white]")

    if not analysis.get("interesting_findings"):
        console.print("  Tidak ada temuan menarik.\n")
    else:
        for item in analysis.get("interesting_findings", []):
            console.print(
                f"  Host: {item.get('ip')} | "
                f"Score: {item.get('score')} | "
                f"Severity: {item.get('severity')} | "
                f"Risk: {item.get('risk_label')}"
            )

            for finding in item.get("findings", []):
                console.print(f"    - {finding}")

            console.print()

    console.print("[bold white]Top Risk Hosts:[/bold white]")
    for item in analysis.get("host_scores", [])[:5]:
        console.print(
            f"  - {item.get('ip')} | "
            f"severity={item.get('severity')} | "
            f"risk={item.get('risk_label')} | "
            f"score={item.get('score')} | "
            f"open_ports={item.get('open_ports')}"
        )

    print_threat_classification(classification)

    ensure_reports_dir()

    output_path = "reports/nmap_report.json"
    try:
        save_json_report(file_path, hosts, analysis, output_path)
        console.print(f"\nJSON report disimpan ke: {output_path}")
    except Exception:
        save_analysis_json(file_path, hosts, analysis, classification, output_path)
        console.print(f"\nJSON report disimpan ke: {output_path}")

    try:
        with open(output_path, "r", encoding="utf-8") as f:
            report_data = json.load(f)

        if "classification" not in report_data:
            report_data["classification"] = classification

        summary = generate_executive_summary(report_data)

        console.print("\n" + summary)

        summary_path = "reports/executive_summary.txt"
        with open(summary_path, "w", encoding="utf-8") as f:
            f.write(summary)

        console.print(f"\nExecutive summary disimpan ke: {summary_path}")
    except Exception as e:
        console.print(f"\n[bold yellow][WARN][/bold yellow] Gagal membuat executive summary: {e}")


def handle_pcap():
    file_path = ask_file_path()

    if not validate_file(file_path):
        return

    console.print("\n[bold cyan][INFO][/bold cyan] Menganalisis file PCAP...\n")

    try:
        with console.status("[bold cyan]Parsing dan menganalisis PCAP...[/bold cyan]", spinner="dots"):
            events = parse_pcap(file_path)
            analysis = analyze_pcap_events(events)
            classification = classify_pcap_threat(analysis)

            timeline = generate_attack_timeline(events, analysis.get("findings", []))
            host_risk = calculate_host_risk(events, analysis.get("findings", []))
            mitre = map_mitre(analysis.get("findings", []))
    except Exception as e:
        console.print(f"[bold red][ERROR][/bold red] Gagal membaca PCAP: {e}")
        return

    console.print("[bold white]=== PCAP Analysis ===[/bold white]\n")

    console.print(f"Total events : {len(events)}")
    console.print(f"Severity     : {analysis.get('severity', 'Unknown')}")
    console.print(f"Risk Label   : {analysis.get('risk_label', 'Unknown')}")
    console.print(f"Score        : {analysis.get('score', 0)}\n")

    overview = analysis.get("network_overview", {})
    tcp_health = analysis.get("tcp_health", {})

    console.print("[bold white]Network Overview:[/bold white]")
    console.print(f"  - Private Hosts          : {overview.get('unique_private_hosts', 0)}")
    console.print(f"  - External Hosts         : {overview.get('unique_external_hosts', 0)}")
    console.print(f"  - Multicast Destinations : {overview.get('unique_multicast_destinations', 0)}")
    console.print(f"  - Broadcast Observations : {overview.get('broadcast_observations', 0)}")

    console.print("\n[bold white]TCP Health Indicators:[/bold white]")
    console.print(f"  - Retransmissions        : {tcp_health.get('tcp_retransmissions', 0)}")
    console.print(f"  - Duplicate ACKs         : {tcp_health.get('duplicate_acks', 0)}")
    console.print(f"  - Out-of-Order Segments  : {tcp_health.get('out_of_order', 0)}")

    console.print("\n[bold white]Top Protocols:[/bold white]")
    for proto, count in analysis.get("top_protocols", []):
        console.print(f"  - {proto}: {count} paket")

    console.print("\n[bold white]Top Sources:[/bold white]")
    for src, count in analysis.get("top_sources", []):
        console.print(f"  - {src}: {count} koneksi")

    console.print("\n[bold white]Top Ports:[/bold white]")
    for port, count in analysis.get("top_ports", []):
        console.print(f"  - {port}: {count} koneksi")

    console.print("\n[bold white]Top Destinations:[/bold white]")
    for dst, count in analysis.get("top_destinations", []):
        console.print(f"  - {dst}: {count} koneksi")

    console.print("\n[bold white]Top External Hosts:[/bold white]")
    if not analysis.get("external_connections"):
        console.print("  Tidak ada koneksi eksternal menonjol.")
    else:
        for ip, count in analysis.get("external_connections", [])[:5]:
            console.print(f"  - {ip}: {count} koneksi")

    console.print("\n[bold white]Known Multicast / Service Discovery:[/bold white]")
    multicast_summary = analysis.get("multicast_summary", [])
    if not multicast_summary:
        console.print("  Tidak ada traffic multicast menonjol.")
    else:
        for item in multicast_summary[:5]:
            console.print(f"  - {item['ip']} | {item['label']} | {item['count']} paket")

    console.print("\n[bold white]Top Talkers:[/bold white]")
    top_talkers = analysis.get("top_talkers", [])
    if not top_talkers:
        console.print("  Tidak ada top talkers yang berhasil dihitung.")
    else:
        for item in top_talkers[:10]:
            console.print(
                f"  - {item['ip']} | "
                f"type={item['type']} | "
                f"sent={item['sent']} | "
                f"received={item['received']} | "
                f"total={item['total']}"
            )

    console.print("\n[bold white]Top Conversation Pairs:[/bold white]")
    conversation_pairs = analysis.get("conversation_pairs", [])
    if not conversation_pairs:
        console.print("  Tidak ada pasangan komunikasi menonjol.")
    else:
        for pair in conversation_pairs[:10]:
            console.print(
                f"  - {pair['src_ip']} -> {pair['dst_ip']} | "
                f"count={pair['count']} | "
                f"bytes={pair['bytes']} | "
                f"protocols={pair['top_protocols']}"
            )

    console.print("\n[bold white]Device Inventory:[/bold white]")
    inventory = analysis.get("device_inventory", [])
    if not inventory:
        console.print("  Tidak ada inventory perangkat yang berhasil disusun.")
    else:
        for device in inventory[:10]:
            roles = ", ".join(device.get("roles", [])) if device.get("roles") else "-"
            macs = ", ".join(device.get("mac_addresses", [])[:2]) if device.get("mac_addresses") else "-"
            hostnames = ", ".join(device.get("hostnames", [])[:2]) if device.get("hostnames") else "-"
            vendors = ", ".join(device.get("vendors", [])[:2]) if device.get("vendors") else "-"
            role_conf = ", ".join(
                f"{x['role']}({x['confidence']})"
                for x in device.get("role_confidence", [])[:3]
            ) if device.get("role_confidence") else "-"

            console.print(
                f"  - IP: {device['ip']} | "
                f"Private: {device['is_private']} | "
                f"Packets: {device['packet_count']} | "
                f"Roles: {roles} | "
                f"Role Confidence: {role_conf} | "
                f"Hostname: {hostnames} | "
                f"Vendor: {vendors} | "
                f"MAC: {macs}"
            )

    console.print("\n[bold white]Top Risk Hosts:[/bold white]")
    if not host_risk:
        console.print("  Tidak ada risk host yang berhasil dihitung.")
    else:
        for item in host_risk[:10]:
            console.print(
                f"  - {item['host']} | "
                f"score={item['score']} | "
                f"risk={item['risk']}"
            )

    console.print("\n[bold white]MITRE ATT&CK Mapping:[/bold white]")
    if not mitre:
        console.print("  Tidak ada mapping MITRE yang cocok.")
    else:
        shown = set()
        for item in mitre:
            key = (item["technique"], item["name"])
            if key in shown:
                continue
            shown.add(key)
            console.print(f"  - {item['technique']} | {item['name']}")

    console.print("\n[bold white]Attack Timeline:[/bold white]")
    attack_steps = timeline.get("attack_steps", [])
    if not attack_steps:
        console.print("  Tidak ada tahapan serangan yang berhasil dipetakan.")
    else:
        for step in attack_steps[:15]:
            console.print(f"  - [{step['phase']}] {step['description']}")

    console.print("\n[bold white]Findings:[/bold white]")
    if not analysis.get("findings"):
        console.print("  Tidak ada temuan menonjol.")
    else:
        for finding in analysis.get("findings", []):
            console.print(
                f"  - [{finding['severity']}/{finding['confidence']}] "
                f"{finding['message']}"
            )

    print_threat_classification(classification)

    output_path = "reports/pcap_report.json"
    try:
        save_analysis_json(
            file_path,
            events,
            analysis,
            classification,
            output_path,
            extra={
                "attack_timeline": timeline,
                "host_risk": host_risk,
                "mitre_mapping": mitre,
            },
        )
        console.print(f"\nJSON report disimpan ke: {output_path}")
    except Exception as e:
        console.print(f"\n[bold yellow][WARN][/bold yellow] Gagal menyimpan report PCAP: {e}")


def handle_syslog():
    file_path = ask_file_path()

    if not validate_file(file_path):
        return

    console.print("\n[bold cyan][INFO][/bold cyan] Menganalisis system log...\n")

    try:
        with console.status("[bold cyan]Parsing dan menganalisis system log...[/bold cyan]", spinner="dots"):
            events = parse_syslog(file_path)
            analysis = analyze_syslog_events(events)
            classification = classify_syslog_threat(analysis)
    except Exception as e:
        console.print(f"[bold red][ERROR][/bold red] Gagal membaca system log: {e}")
        return

    console.print("[bold white]=== System Log Analysis ===[/bold white]\n")

    console.print(f"Total events : {len(events)}")
    console.print(f"Severity     : {analysis.get('severity', 'Unknown')}")
    console.print(f"Risk Label   : {analysis.get('risk_label', 'Unknown')}")
    console.print(f"Score        : {analysis.get('score', 0)}\n")

    console.print("[bold white]Event Counts:[/bold white]")
    for event_type, count in analysis.get("event_counts", {}).items():
        console.print(f"  - {event_type}: {count}")

    console.print("\n[bold white]Failed Login By IP:[/bold white]")
    if not analysis.get("failed_by_ip"):
        console.print("  Tidak ada failed login menonjol.")
    else:
        for ip, count in analysis.get("failed_by_ip", []):
            console.print(f"  - {ip}: {count}")

    console.print("\n[bold white]Invalid User Attempts:[/bold white]")
    if not analysis.get("invalid_user_by_ip"):
        console.print("  Tidak ada invalid user menonjol.")
    else:
        for ip, count in analysis.get("invalid_user_by_ip", []):
            console.print(f"  - {ip}: {count}")

    console.print("\n[bold white]Successful Logins:[/bold white]")
    if not analysis.get("success_by_ip"):
        console.print("  Tidak ada login sukses terdeteksi.")
    else:
        for ip, count in analysis.get("success_by_ip", []):
            console.print(f"  - {ip}: {count}")

    console.print("\n[bold white]Findings:[/bold white]")
    if not analysis.get("findings"):
        console.print("  Tidak ada temuan menonjol.")
    else:
        for finding in analysis.get("findings", []):
            console.print(f"  - {finding}")

    print_threat_classification(classification)

    output_path = "reports/syslog_report.json"
    try:
        save_analysis_json(file_path, events, analysis, classification, output_path)
        console.print(f"\nJSON report disimpan ke: {output_path}")
    except Exception as e:
        console.print(f"\n[bold yellow][WARN][/bold yellow] Gagal menyimpan report system log: {e}")


def main():
    ensure_reports_dir()

    show_banner(version="v1.1.2", repo_label="karya_mahasiswa/netlog")
    show_startup_animation()

    while True:
        print_banner()
        choice = input("\nPilih opsi: ").strip()

        if choice == "1":
            handle_nmap()
        elif choice == "2":
            handle_pcap()
        elif choice == "3":
            handle_syslog()
        elif choice == "0":
            console.print("[bold red]Keluar dari program.[/bold red]")
            break
        else:
            console.print("[bold yellow]Pilihan tidak valid. Coba lagi.[/bold yellow]")


if __name__ == "__main__":
    main()