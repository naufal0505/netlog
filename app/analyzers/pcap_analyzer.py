from collections import Counter, defaultdict
from statistics import mean, pstdev
from datetime import datetime
import ipaddress
import math

BROADCAST_IPS = {"255.255.255.255"}
IGNORED_SOURCE_IPS = {"0.0.0.0", "unknown", None}

COMMON_LOCAL_PORTS = {
    67,   # DHCP
    68,   # DHCP
    137,  # NetBIOS
    138,  # NetBIOS
    139   # NetBIOS Session
}

COMMON_SERVICE_PORTS = {
    5060: "SIP",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
}

SENSITIVE_PORTS = {
    22: "SSH",
    23: "Telnet",
    445: "SMB",
    3389: "RDP",
    5900: "VNC",
    1433: "MSSQL",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
}

SUSPICIOUS_EXTERNAL_PORTS = {
    4444: "Metasploit / Reverse Shell",
    5555: "Suspicious Service",
    6666: "IRC / Suspicious Service",
    1337: "Backdoor / Suspicious Service",
    31337: "Back Orifice / Suspicious Service",
    9001: "Tunnel / Proxy / Suspicious Service",
}

KNOWN_MULTICAST_LABELS = {
    "224.0.0.251": "mDNS",
    "224.0.0.252": "LLMNR",
    "239.255.255.250": "SSDP/UPnP",
    "224.0.0.1": "All Hosts Multicast",
    "224.0.0.2": "All Routers Multicast",
}


def is_broadcast_ip(ip: str) -> bool:
    if not ip or ip == "unknown":
        return False
    if ip in BROADCAST_IPS:
        return True
    return ip.endswith(".255")


def is_multicast_ip(ip: str) -> bool:
    if not ip or ip == "unknown":
        return False
    try:
        return ipaddress.ip_address(ip).is_multicast
    except ValueError:
        return False


def is_private_ip(ip: str) -> bool:
    if not ip or ip == "unknown":
        return False
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def is_valid_source(ip: str) -> bool:
    if ip in IGNORED_SOURCE_IPS:
        return False
    if is_broadcast_ip(ip):
        return False
    return True


def add_finding(findings: list, finding_type: str, severity: str, confidence: str, message: str):
    findings.append({
        "type": finding_type,
        "severity": severity,
        "confidence": confidence,
        "message": message,
    })


def parse_timestamp(ts):
    if not ts:
        return None

    if isinstance(ts, datetime):
        return ts

    if isinstance(ts, (int, float)):
        try:
            return datetime.fromtimestamp(ts)
        except Exception:
            return None

    ts = str(ts).strip()

    formats = [
        None,
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%d/%m/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M:%S.%f",
    ]

    for fmt in formats:
        try:
            if fmt is None:
                return datetime.fromisoformat(ts)
            return datetime.strptime(ts, fmt)
        except Exception:
            continue

    return None


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0

    freq = Counter(text)
    length = len(text)
    entropy = 0.0

    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)

    return entropy


def infer_roles_and_confidence(ip: str, protocol_counter: Counter, port_counter: Counter, hostnames: set, vendors: set):
    role_scores = defaultdict(int)

    if is_private_ip(ip) and ip.endswith(".1"):
        role_scores["possible_gateway"] += 5

    if protocol_counter.get("arp", 0) >= 10:
        role_scores["lan_participant"] += 2

    if port_counter.get(53, 0) >= 5:
        role_scores["possible_dns_server"] += 4

    if port_counter.get(67, 0) >= 2 or port_counter.get(68, 0) >= 2:
        role_scores["dhcp_participant"] += 3

    if sum(port_counter.get(p, 0) for p in [80, 443, 8080, 8443]) >= 5:
        role_scores["possible_web_service"] += 4

    if sum(port_counter.get(p, 0) for p in [80, 443, 8080, 8443]) >= 3:
        role_scores["web_client"] += 2

    if sum(port_counter.get(p, 0) for p in [22, 3389, 445, 139]) >= 3:
        role_scores["possible_admin_or_file_service"] += 4

    if sum(port_counter.get(p, 0) for p in [9100, 515, 631]) >= 2:
        role_scores["possible_printer"] += 5

    if sum(port_counter.get(p, 0) for p in [554, 8000, 8009, 8554]) >= 2:
        role_scores["possible_camera_or_media_device"] += 4

    if protocol_counter.get("arp", 0) >= 5 and protocol_counter.get("udp", 0) >= 10:
        role_scores["active_lan_host"] += 2

    if hostnames:
        role_scores["named_asset"] += 1

    if vendors:
        role_scores["identified_vendor_asset"] += 1

    result = []
    for role, score in sorted(role_scores.items(), key=lambda x: x[1], reverse=True):
        if score >= 5:
            confidence = "High"
        elif score >= 3:
            confidence = "Medium"
        else:
            confidence = "Low"

        result.append({
            "role": role,
            "confidence": confidence,
            "score": score,
        })

    return result


def build_device_inventory(events: list[dict]) -> list[dict]:
    devices = {}

    for event in events:
        data = event.get("data", {})

        src_ip = data.get("src_ip")
        dst_ip = data.get("dst_ip")
        src_mac = data.get("src_mac")
        dst_mac = data.get("dst_mac")
        src_port = data.get("src_port")
        dst_port = data.get("dst_port")
        protocol = str(data.get("protocol", "unknown")).lower()
        dhcp_hostname = data.get("dhcp_hostname")
        dhcp_vendor = data.get("dhcp_vendor")

        if src_ip and src_ip != "unknown":
            if src_ip not in devices:
                devices[src_ip] = {
                    "ip": src_ip,
                    "mac_addresses": set(),
                    "hostnames": set(),
                    "vendors": set(),
                    "protocols": Counter(),
                    "ports": Counter(),
                    "is_private": is_private_ip(src_ip),
                    "packet_count": 0,
                }

            devices[src_ip]["packet_count"] += 1
            devices[src_ip]["protocols"][protocol] += 1

            if src_mac:
                devices[src_ip]["mac_addresses"].add(src_mac)
            if dhcp_hostname:
                devices[src_ip]["hostnames"].add(dhcp_hostname)
            if dhcp_vendor:
                devices[src_ip]["vendors"].add(dhcp_vendor)
            if src_port is not None:
                devices[src_ip]["ports"][src_port] += 1
            if dst_port is not None:
                devices[src_ip]["ports"][dst_port] += 1

        if dst_ip and dst_ip != "unknown" and not is_multicast_ip(dst_ip) and not is_broadcast_ip(dst_ip):
            if dst_ip not in devices:
                devices[dst_ip] = {
                    "ip": dst_ip,
                    "mac_addresses": set(),
                    "hostnames": set(),
                    "vendors": set(),
                    "protocols": Counter(),
                    "ports": Counter(),
                    "is_private": is_private_ip(dst_ip),
                    "packet_count": 0,
                }

            if dst_mac:
                devices[dst_ip]["mac_addresses"].add(dst_mac)
            if dst_port is not None:
                devices[dst_ip]["ports"][dst_port] += 1

        # protocol destination visibility
        if dst_ip and dst_ip != "unknown" and dst_ip in devices:
            devices[dst_ip]["protocols"][protocol] += 1

    inventory = []
    for ip, item in devices.items():
        role_confidence = infer_roles_and_confidence(
            ip,
            item["protocols"],
            item["ports"],
            item["hostnames"],
            item["vendors"],
        )

        inventory.append({
            "ip": item["ip"],
            "is_private": item["is_private"],
            "packet_count": item["packet_count"],
            "mac_addresses": sorted(item["mac_addresses"]),
            "hostnames": sorted(item["hostnames"]),
            "vendors": sorted(item["vendors"]),
            "roles": [x["role"] for x in role_confidence],
            "role_confidence": role_confidence[:5],
            "top_protocols": item["protocols"].most_common(5),
            "top_ports": item["ports"].most_common(5),
        })

    inventory.sort(key=lambda x: x["packet_count"], reverse=True)
    return inventory


def detect_tcp_health_issues(events: list[dict]) -> dict:
    flow_sequences = defaultdict(set)
    retransmissions = 0
    duplicate_acks = 0
    out_of_order = 0

    last_ack_seen = defaultdict(lambda: None)
    last_seq_seen = defaultdict(lambda: None)

    for event in events:
        data = event.get("data", {})

        protocol = str(data.get("protocol", "")).lower()
        if protocol != "tcp":
            continue

        src_ip = data.get("src_ip")
        dst_ip = data.get("dst_ip")
        src_port = data.get("src_port")
        dst_port = data.get("dst_port")
        seq = data.get("tcp_seq")
        ack = data.get("tcp_ack")

        if not src_ip or not dst_ip or src_port is None or dst_port is None:
            continue

        flow = (src_ip, dst_ip, src_port, dst_port)

        if seq is not None:
            if seq in flow_sequences[flow]:
                retransmissions += 1
            else:
                flow_sequences[flow].add(seq)

            prev_seq = last_seq_seen[flow]
            if prev_seq is not None and seq < prev_seq:
                out_of_order += 1
            last_seq_seen[flow] = seq

        if ack is not None:
            prev_ack = last_ack_seen[flow]
            if prev_ack is not None and ack == prev_ack:
                duplicate_acks += 1
            last_ack_seen[flow] = ack

    health_findings = []
    score_add = 0

    if retransmissions >= 20:
        health_findings.append(
            "Possible packet loss atau network instability terindikasi dari jumlah TCP retransmission yang cukup tinggi."
        )
        score_add += 2
    elif retransmissions >= 5:
        health_findings.append(
            "Terdapat TCP retransmission dalam jumlah moderat yang bisa mengindikasikan gangguan kualitas jaringan."
        )
        score_add += 1

    if duplicate_acks >= 20:
        health_findings.append(
            "Duplicate ACK terdeteksi dalam jumlah tinggi, yang sering berkaitan dengan packet loss atau segment tidak berurutan."
        )
        score_add += 2
    elif duplicate_acks >= 5:
        health_findings.append(
            "Terdapat duplicate ACK dalam jumlah moderat yang perlu divalidasi terhadap kualitas koneksi."
        )
        score_add += 1

    if out_of_order >= 10:
        health_findings.append(
            "Out-of-order TCP segments terdeteksi, yang dapat berkaitan dengan retransmission, packet reordering, atau gangguan jaringan."
        )
        score_add += 1

    return {
        "tcp_retransmissions": retransmissions,
        "duplicate_acks": duplicate_acks,
        "out_of_order": out_of_order,
        "health_findings": health_findings,
        "score_add": score_add,
    }


def build_network_overview(events: list[dict]) -> dict:
    private_hosts = set()
    external_hosts = set()
    multicast_hosts = set()
    broadcast_count = 0

    for event in events:
        data = event.get("data", {})
        src_ip = data.get("src_ip")
        dst_ip = data.get("dst_ip")

        for ip in [src_ip, dst_ip]:
            if not ip or ip == "unknown":
                continue
            if is_broadcast_ip(ip):
                broadcast_count += 1
            elif is_multicast_ip(ip):
                multicast_hosts.add(ip)
            elif is_private_ip(ip):
                private_hosts.add(ip)
            else:
                external_hosts.add(ip)

    return {
        "unique_private_hosts": len(private_hosts),
        "unique_external_hosts": len(external_hosts),
        "unique_multicast_destinations": len(multicast_hosts),
        "broadcast_observations": broadcast_count,
    }


def build_multicast_summary(dst_counter: Counter) -> list[dict]:
    items = []
    for ip, count in dst_counter.items():
        if is_multicast_ip(ip):
            items.append({
                "ip": ip,
                "count": count,
                "label": KNOWN_MULTICAST_LABELS.get(ip, "Unknown Multicast"),
            })

    items.sort(key=lambda x: x["count"], reverse=True)
    return items[:10]


def build_top_talkers(src_counter: Counter, dst_counter: Counter) -> list[dict]:
    all_ips = set(src_counter.keys()) | set(dst_counter.keys())
    talkers = []

    for ip in all_ips:
        if not ip or ip == "unknown":
            continue
        sent = src_counter.get(ip, 0)
        received = dst_counter.get(ip, 0)
        total = sent + received

        talkers.append({
            "ip": ip,
            "sent": sent,
            "received": received,
            "total": total,
            "is_private": is_private_ip(ip),
            "type": "private" if is_private_ip(ip) else "external",
        })

    talkers.sort(key=lambda x: x["total"], reverse=True)
    return talkers[:15]


def build_conversation_pairs(pair_counter: Counter, pair_bytes: Counter, pair_protocols: dict) -> list[dict]:
    pairs = []

    for (src_ip, dst_ip), count in pair_counter.items():
        if not src_ip or not dst_ip:
            continue
        if src_ip == "unknown" or dst_ip == "unknown":
            continue

        pairs.append({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "count": count,
            "bytes": pair_bytes.get((src_ip, dst_ip), 0),
            "top_protocols": pair_protocols.get((src_ip, dst_ip), Counter()).most_common(3),
            "src_private": is_private_ip(src_ip),
            "dst_private": is_private_ip(dst_ip),
        })

    pairs.sort(key=lambda x: (x["count"], x["bytes"]), reverse=True)
    return pairs[:15]


def detect_port_scan(flow_events, findings):
    score_add = 0

    for (src_ip, dst_ip), events in flow_events.items():
        if not src_ip or not dst_ip:
            continue
        if src_ip == "unknown" or dst_ip == "unknown":
            continue
        if is_broadcast_ip(dst_ip) or is_multicast_ip(dst_ip):
            continue

        events = [e for e in events if e[0] is not None and e[1] is not None and e[2] == "tcp"]
        if len(events) < 5:
            continue

        events.sort(key=lambda x: x[0])

        start = 0
        for end in range(len(events)):
            while start <= end and (events[end][0] - events[start][0]).total_seconds() > 60:
                start += 1

            ports_in_window = {port for _, port, proto in events[start:end + 1] if port is not None}
            port_count = len(ports_in_window)

            if port_count >= 20:
                add_finding(
                    findings,
                    "port_scan",
                    "High",
                    "High",
                    f"Possible port scanning: sumber {src_ip} mengakses {port_count} port TCP berbeda pada target {dst_ip} dalam 60 detik."
                )
                score_add += 5
                break
            elif port_count >= 12:
                add_finding(
                    findings,
                    "port_scan",
                    "Medium",
                    "Medium",
                    f"Indikasi scanning: sumber {src_ip} mengakses {port_count} port TCP berbeda pada target {dst_ip} dalam 60 detik."
                )
                score_add += 3
                break

    return score_add


def analyze_pcap_events(events: list[dict]) -> dict:
    port_counter = Counter()
    dst_counter = Counter()
    protocol_counter = Counter()
    src_counter = Counter()

    src_to_internal_hosts = defaultdict(set)
    src_to_target_port_counts = defaultdict(Counter)
    external_connections = Counter()

    flow_timestamps = defaultdict(list)
    flow_events = defaultdict(list)
    dns_stats_by_src = defaultdict(list)
    external_host_stats = defaultdict(lambda: {
        "count": 0,
        "src_hosts": set(),
        "ports": [],
    })

    pair_counter = Counter()
    pair_bytes = Counter()
    pair_protocols = defaultdict(Counter)

    findings = []
    score = 0

    for event in events:
        data = event.get("data", {})

        src_ip = data.get("src_ip")
        dst_ip = data.get("dst_ip")
        src_port = data.get("src_port")
        dst_port = data.get("dst_port")
        protocol = str(data.get("protocol", "unknown")).lower()
        protocols = data.get("protocols", "")
        timestamp = parse_timestamp(data.get("timestamp"))
        length = data.get("length", 0) or 0

        dns_query = data.get("dns_query") or data.get("query_name") or data.get("dns_name")
        dns_rcode = str(data.get("dns_rcode", data.get("rcode", "UNKNOWN"))).upper()

        protocol_counter[protocol] += 1

        if src_ip:
            src_counter[src_ip] += 1
        if dst_ip:
            dst_counter[dst_ip] += 1
        if dst_port is not None:
            port_counter[dst_port] += 1

        if src_ip and dst_ip and src_ip != "unknown" and dst_ip != "unknown":
            pair_counter[(src_ip, dst_ip)] += 1
            pair_bytes[(src_ip, dst_ip)] += length
            pair_protocols[(src_ip, dst_ip)][protocol] += 1

        if (
            is_valid_source(src_ip)
            and dst_ip
            and is_private_ip(dst_ip)
            and not is_broadcast_ip(dst_ip)
            and not is_multicast_ip(dst_ip)
            and protocol == "tcp"
        ):
            src_to_internal_hosts[src_ip].add(dst_ip)

        if is_valid_source(src_ip) and dst_ip and dst_port is not None:
            key = f"{dst_ip}:{dst_port}"
            src_to_target_port_counts[src_ip][key] += 1

        if is_valid_source(src_ip) and dst_ip and dst_port is not None and timestamp:
            flow_timestamps[(src_ip, dst_ip, dst_port)].append(timestamp)
            flow_events[(src_ip, dst_ip)].append((timestamp, dst_port, protocol))

        if (
            is_valid_source(src_ip)
            and dst_ip
            and dst_ip != "unknown"
            and not is_private_ip(dst_ip)
            and not is_broadcast_ip(dst_ip)
            and not is_multicast_ip(dst_ip)
        ):
            external_connections[dst_ip] += 1
            external_host_stats[dst_ip]["count"] += 1
            external_host_stats[dst_ip]["src_hosts"].add(src_ip)
            if dst_port is not None:
                external_host_stats[dst_ip]["ports"].append(dst_port)

        is_dns = (
            protocol == "dns"
            or src_port == 53
            or dst_port == 53
            or "DNS" in str(protocols).upper()
            or dns_query is not None
        )
        if is_valid_source(src_ip) and is_dns:
            dns_stats_by_src[src_ip].append({
                "query": dns_query,
                "rcode": dns_rcode,
            })

    # Baseline service findings
    for port, count in port_counter.items():
        if port in COMMON_LOCAL_PORTS:
            if count >= 200:
                add_finding(
                    findings,
                    "local_lan_traffic",
                    "Low",
                    "Low",
                    f"Traffic tinggi ke port lokal umum {port}: {count} koneksi (kemungkinan normal di LAN, perlu validasi konteks)."
                )
            continue

        if port in COMMON_SERVICE_PORTS:
            threshold = 80 if port == 5060 else 100
            if count >= threshold:
                add_finding(
                    findings,
                    "common_service_activity",
                    "Low",
                    "Low",
                    f"Traffic tinggi ke service umum {port} ({COMMON_SERVICE_PORTS[port]}): {count} koneksi (bisa normal tergantung role host)."
                )
            continue

        if port in SENSITIVE_PORTS and count >= 25:
            add_finding(
                findings,
                "sensitive_port_activity",
                "Medium",
                "Medium",
                f"Traffic signifikan ke port sensitif {port} ({SENSITIVE_PORTS[port]}): {count} koneksi."
            )
            score += 2
            continue

        if count >= 60:
            add_finding(
                findings,
                "high_port_volume",
                "Low",
                "Low",
                f"Traffic tinggi menuju port {port}: {count} koneksi."
            )
            score += 1

    # Port scanning
    score += detect_port_scan(flow_events, findings)

    # SSH activity / brute force
    ssh_count = port_counter.get(22, 0)
    if ssh_count >= 50:
        add_finding(
            findings,
            "ssh_activity",
            "Medium",
            "Medium",
            f"Indikasi aktivitas SSH tinggi: {ssh_count} koneksi menuju port 22."
        )
        score += 2

    for src_ip, target_counts in src_to_target_port_counts.items():
        ssh_targets = {
            target: count for target, count in target_counts.items()
            if target.endswith(":22")
        }

        for target, count in ssh_targets.items():
            if count >= 80:
                add_finding(
                    findings,
                    "ssh_bruteforce",
                    "High",
                    "High",
                    f"Possible SSH brute force dari {src_ip} ke {target}: {count} koneksi."
                )
                score += 6
            elif count >= 40:
                add_finding(
                    findings,
                    "ssh_suspicious",
                    "Medium",
                    "Medium",
                    f"Suspicious SSH activity dari {src_ip} ke {target}: {count} koneksi."
                )
                score += 2

    # Lateral movement
    for src_ip, internal_hosts in src_to_internal_hosts.items():
        host_count = len(internal_hosts)

        if host_count >= 20:
            add_finding(
                findings,
                "lateral_movement",
                "High",
                "Medium",
                f"Possible lateral movement: {src_ip} berkomunikasi dengan {host_count} host internal berbeda."
            )
            score += 4
        elif host_count >= 10:
            add_finding(
                findings,
                "internal_spread",
                "Low",
                "Low",
                f"Internal spread activity: {src_ip} mengakses {host_count} host internal."
            )
            score += 1

    # Beaconing
    for (src_ip, dst_ip, dst_port), timestamps in flow_timestamps.items():
        if len(timestamps) < 5:
            continue

        timestamps.sort()
        intervals = [
            (timestamps[i] - timestamps[i - 1]).total_seconds()
            for i in range(1, len(timestamps))
        ]

        if len(intervals) < 4:
            continue

        avg_interval = mean(intervals)
        stddev_interval = pstdev(intervals) if len(intervals) > 1 else 0

        if avg_interval <= 0:
            continue

        if stddev_interval <= 1 and len(timestamps) >= 5:
            add_finding(
                findings,
                "beaconing_pattern",
                "High",
                "High",
                f"Possible beaconing: {src_ip} -> {dst_ip}:{dst_port} dengan interval stabil rata-rata {avg_interval:.2f} detik (stddev {stddev_interval:.2f}, total {len(timestamps)} koneksi)."
            )
            score += 6
        elif stddev_interval <= 3 and len(timestamps) >= 5:
            add_finding(
                findings,
                "beaconing_pattern",
                "Medium",
                "Medium",
                f"Indikasi beaconing: {src_ip} -> {dst_ip}:{dst_port} dengan interval cukup stabil rata-rata {avg_interval:.2f} detik (stddev {stddev_interval:.2f}, total {len(timestamps)} koneksi)."
            )
            score += 3

    # DNS anomaly
    for src_ip, dns_records in dns_stats_by_src.items():
        total_queries = len(dns_records)
        if total_queries == 0:
            continue

        queries = [r["query"] for r in dns_records if r.get("query")]
        unique_queries = set(queries)
        unique_count = len(unique_queries)

        nxdomain_count = sum(1 for r in dns_records if r.get("rcode") == "NXDOMAIN")
        nxdomain_ratio = (nxdomain_count / total_queries) if total_queries else 0

        long_domains = [q for q in queries if len(q) >= 45]
        high_entropy_domains = [q for q in queries if shannon_entropy(q) >= 3.8]

        reasons = []

        if total_queries >= 50:
            reasons.append(f"volume DNS tinggi ({total_queries} query)")
        if unique_count >= 30:
            reasons.append(f"banyak domain unik ({unique_count})")
        if nxdomain_ratio >= 0.4:
            reasons.append(f"rasio NXDOMAIN tinggi ({nxdomain_ratio:.2f})")
        if len(long_domains) >= 5:
            reasons.append(f"banyak domain panjang ({len(long_domains)})")
        if len(high_entropy_domains) >= 5:
            reasons.append(f"banyak domain entropy tinggi ({len(high_entropy_domains)})")

        if len(reasons) >= 3:
            sample_domains = list(unique_queries)[:5]
            add_finding(
                findings,
                "dns_anomaly",
                "High",
                "High",
                f"DNS anomaly dari {src_ip}: {', '.join(reasons)}. Contoh domain: {sample_domains}"
            )
            score += 6
        elif len(reasons) >= 2:
            sample_domains = list(unique_queries)[:5]
            add_finding(
                findings,
                "dns_anomaly",
                "Medium",
                "Medium",
                f"Indikasi DNS anomaly dari {src_ip}: {', '.join(reasons)}. Contoh domain: {sample_domains}"
            )
            score += 3

    # Unknown / ARP / broadcast
    unknown_count = dst_counter.get("unknown", 0)
    if unknown_count >= 300:
        add_finding(
            findings,
            "non_ip_or_arp",
            "Low",
            "Low",
            f"Banyak paket tanpa dst_ip terpetakan ({unknown_count}); kemungkinan ARP/non-IP/broadcast."
        )

    broadcast_targets = {
        ip: count for ip, count in dst_counter.items() if is_broadcast_ip(ip)
    }
    for ip, count in sorted(broadcast_targets.items(), key=lambda x: x[1], reverse=True)[:5]:
        if count >= 50:
            add_finding(
                findings,
                "broadcast_traffic",
                "Low",
                "Low",
                f"Traffic broadcast terdeteksi ke {ip}: {count} paket (sering normal pada jaringan lokal)."
            )

    # External connection
    for ip, count in external_connections.most_common(5):
        if count >= 20:
            add_finding(
                findings,
                "external_connection",
                "Medium",
                "Medium",
                f"Koneksi berulang ke host eksternal {ip}: {count} koneksi."
            )
            score += 3
        elif count >= 5:
            add_finding(
                findings,
                "external_connection",
                "Low",
                "Low",
                f"Aktivitas ke host eksternal {ip}: {count} koneksi."
            )
            score += 1

    # Suspicious external host
    for ip, stat in sorted(external_host_stats.items(), key=lambda x: x[1]["count"], reverse=True)[:10]:
        count = stat["count"]
        unique_internal_hosts = len(stat["src_hosts"])
        ports = stat["ports"]
        unique_ports = len(set(ports))
        suspicious_port_hits = sum(1 for p in ports if p in SUSPICIOUS_EXTERNAL_PORTS)

        reasons = []

        if count >= 20:
            reasons.append(f"koneksi tinggi ({count})")
        if unique_internal_hosts >= 5:
            reasons.append(f"diakses banyak host internal ({unique_internal_hosts})")
        if unique_ports >= 10:
            reasons.append(f"banyak port target ({unique_ports})")
        if suspicious_port_hits >= 3:
            reasons.append(f"sering ke port mencurigakan ({suspicious_port_hits})")

        if suspicious_port_hits >= 3 and count >= 10:
            add_finding(
                findings,
                "suspicious_external_host",
                "High",
                "High",
                f"Suspicious external host {ip}: {', '.join(reasons)}."
            )
            score += 6
        elif len(reasons) >= 2:
            add_finding(
                findings,
                "suspicious_external_host",
                "Medium",
                "Medium",
                f"Indikasi host eksternal mencurigakan {ip}: {', '.join(reasons)}."
            )
            score += 3

    # Summary builders
    multicast_summary = build_multicast_summary(dst_counter)
    device_inventory = build_device_inventory(events)
    tcp_health = detect_tcp_health_issues(events)
    network_overview = build_network_overview(events)
    top_talkers = build_top_talkers(src_counter, dst_counter)
    conversation_pairs = build_conversation_pairs(pair_counter, pair_bytes, pair_protocols)

    for item in tcp_health["health_findings"]:
        add_finding(findings, "network_health", "Low", "Medium", item)

    for item in multicast_summary[:5]:
        if item["count"] >= 50:
            add_finding(
                findings,
                "service_discovery",
                "Low",
                "High",
                f"Traffic multicast teridentifikasi sebagai {item['label']} menuju {item['ip']}: {item['count']} paket."
            )

    score += tcp_health["score_add"]

    severity = "Low"
    if score >= 12:
        severity = "High"
    elif score >= 5:
        severity = "Medium"

    risk_label = "Informational"
    if score >= 12:
        risk_label = "Priority Review"
    elif score >= 5:
        risk_label = "Monitor"

    return {
        "top_ports": port_counter.most_common(10),
        "top_destinations": dst_counter.most_common(10),
        "top_protocols": protocol_counter.most_common(10),
        "top_sources": src_counter.most_common(10),
        "top_talkers": top_talkers,
        "conversation_pairs": conversation_pairs,
        "external_connections": external_connections.most_common(10),
        "network_overview": network_overview,
        "multicast_summary": multicast_summary,
        "device_inventory": device_inventory[:20],
        "tcp_health": {
            "tcp_retransmissions": tcp_health["tcp_retransmissions"],
            "duplicate_acks": tcp_health["duplicate_acks"],
            "out_of_order": tcp_health["out_of_order"],
        },
        "score": score,
        "severity": severity,
        "risk_label": risk_label,
        "findings": findings,
    }