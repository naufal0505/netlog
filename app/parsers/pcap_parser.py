import json
import os
import shutil
import subprocess
from datetime import datetime

from app.normalizers.event_schema import make_event


def get_tshark_path() -> str:
    tshark_cmd = shutil.which("tshark")
    if tshark_cmd:
        return tshark_cmd

    windows_path = r"C:\Program Files\Wireshark\tshark.exe"
    if os.path.exists(windows_path):
        return windows_path

    raise FileNotFoundError(
        "tshark tidak ditemukan. Install Wireshark/tshark atau tambahkan ke PATH."
    )


def _first(value, default=None):
    if value is None:
        return default
    if isinstance(value, list):
        return value[0] if value else default
    return value


def _safe_int(value, default=None):
    try:
        if value in (None, "", "unknown"):
            return default
        return int(str(value))
    except Exception:
        return default


def _safe_float(value, default=None):
    try:
        if value in (None, "", "unknown"):
            return default
        return float(str(value))
    except Exception:
        return default


def _safe_datetime_from_epoch(value):
    try:
        if value in (None, "", "unknown"):
            return None
        return datetime.fromtimestamp(float(value))
    except Exception:
        return None


def _normalize_dns_rcode(rcode):
    if rcode is None:
        return None

    rcode_str = str(rcode).strip()

    # tshark biasanya kasih angka
    mapping = {
        "0": "NOERROR",
        "1": "FORMERR",
        "2": "SERVFAIL",
        "3": "NXDOMAIN",
        "4": "NOTIMP",
        "5": "REFUSED",
        "6": "YXDOMAIN",
        "7": "YXRRSET",
        "8": "NXRRSET",
        "9": "NOTAUTH",
        "10": "NOTZONE",
    }

    return mapping.get(rcode_str, rcode_str.upper())


def parse_pcap(file_path: str) -> list[dict]:
    tshark_path = get_tshark_path()

    cmd = [
        tshark_path,
        "-r",
        file_path,
        "-T",
        "json",
        "-e",
        "frame.time_epoch",
        "-e",
        "frame.len",
        "-e",
        "frame.protocols",
        "-e",
        "eth.src",
        "-e",
        "eth.dst",
        "-e",
        "ip.src",
        "-e",
        "ip.dst",
        "-e",
        "ipv6.src",
        "-e",
        "ipv6.dst",
        "-e",
        "arp.src.proto_ipv4",
        "-e",
        "arp.dst.proto_ipv4",
        "-e",
        "tcp.srcport",
        "-e",
        "tcp.dstport",
        "-e",
        "udp.srcport",
        "-e",
        "udp.dstport",
        "-e",
        "tcp.seq",
        "-e",
        "tcp.ack",
        "-e",
        "dns.qry.name",
        "-e",
        "dns.flags.rcode",
        "-e",
        "bootp.option.hostname",
        "-e",
        "bootp.option.vendor_class_id",
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        raise RuntimeError(f"tshark error: {result.stderr}")

    try:
        packets = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Gagal parse output JSON dari tshark: {e}")

    events = []

    for pkt in packets:
        try:
            layers = pkt.get("_source", {}).get("layers", {})

            frame_protocols = _first(layers.get("frame.protocols"), "") or ""
            frame_len = _safe_int(_first(layers.get("frame.len"), None), None)
            time_epoch = _first(layers.get("frame.time_epoch"), None)
            parsed_timestamp = _safe_datetime_from_epoch(time_epoch)

            eth_src = _first(layers.get("eth.src"), None)
            eth_dst = _first(layers.get("eth.dst"), None)

            ip_src = _first(layers.get("ip.src"), None)
            ip_dst = _first(layers.get("ip.dst"), None)

            ipv6_src = _first(layers.get("ipv6.src"), None)
            ipv6_dst = _first(layers.get("ipv6.dst"), None)

            arp_src = _first(layers.get("arp.src.proto_ipv4"), None)
            arp_dst = _first(layers.get("arp.dst.proto_ipv4"), None)

            src_ip = ip_src or ipv6_src or arp_src or "unknown"
            dst_ip = ip_dst or ipv6_dst or arp_dst or "unknown"

            tcp_src = _first(layers.get("tcp.srcport"), None)
            tcp_dst = _first(layers.get("tcp.dstport"), None)
            udp_src = _first(layers.get("udp.srcport"), None)
            udp_dst = _first(layers.get("udp.dstport"), None)

            tcp_seq = _safe_int(_first(layers.get("tcp.seq"), None), None)
            tcp_ack = _safe_int(_first(layers.get("tcp.ack"), None), None)

            dns_query = _first(layers.get("dns.qry.name"), None)
            dns_rcode = _normalize_dns_rcode(_first(layers.get("dns.flags.rcode"), None))

            dhcp_hostname = _first(layers.get("bootp.option.hostname"), None)
            dhcp_vendor = _first(layers.get("bootp.option.vendor_class_id"), None)

            protocol = "unknown"
            src_port = None
            dst_port = None

            # Prioritaskan DNS kalau ada field DNS
            if dns_query is not None or "dns" in frame_protocols:
                protocol = "dns"

                if tcp_dst or tcp_src:
                    src_port = _safe_int(tcp_src, None)
                    dst_port = _safe_int(tcp_dst, None)
                elif udp_dst or udp_src:
                    src_port = _safe_int(udp_src, None)
                    dst_port = _safe_int(udp_dst, None)
                else:
                    src_port = 53
                    dst_port = 53

            elif tcp_dst or tcp_src:
                protocol = "tcp"
                src_port = _safe_int(tcp_src, None)
                dst_port = _safe_int(tcp_dst, None)

            elif udp_dst or udp_src:
                protocol = "udp"
                src_port = _safe_int(udp_src, None)
                dst_port = _safe_int(udp_dst, None)

            elif "arp" in frame_protocols:
                protocol = "arp"

            elif "icmpv6" in frame_protocols:
                protocol = "icmpv6"

            elif "icmp" in frame_protocols:
                protocol = "icmp"

            elif "ipv6" in frame_protocols:
                protocol = "ipv6"

            elif "ip" in frame_protocols:
                protocol = "ip"

            events.append(
                make_event(
                    source="pcap",
                    event_type="network_connection",
                    host=dst_ip,
                    severity="info",
                    data={
                        "timestamp": parsed_timestamp,
                        "length": frame_len,
                        "protocol": protocol,
                        "protocols": frame_protocols,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "src_mac": eth_src,
                        "dst_mac": eth_dst,
                        "tcp_seq": tcp_seq,
                        "tcp_ack": tcp_ack,
                        "dns_query": dns_query,
                        "dns_rcode": dns_rcode,
                        "dhcp_hostname": dhcp_hostname,
                        "dhcp_vendor": dhcp_vendor,
                    },
                )
            )

        except Exception:
            # skip paket yang bermasalah supaya parsing tidak gagal total
            continue

    return events