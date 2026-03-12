import re
import xml.etree.ElementTree as ET


COMMON_PORT_SERVICES = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    67: "dhcp",
    68: "dhcp",
    69: "tftp",
    80: "http",
    88: "kerberos",
    110: "pop3",
    111: "rpcbind",
    123: "ntp",
    135: "msrpc",
    137: "netbios-ns",
    138: "netbios-dgm",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    389: "ldap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    514: "syslog",
    587: "submission",
    631: "ipp",
    993: "imaps",
    995: "pop3s",
    1433: "ms-sql-s",
    1521: "oracle",
    1723: "pptp",
    1883: "mqtt",
    2049: "nfs",
    2375: "docker",
    2376: "docker-ssl",
    3306: "mysql",
    3389: "ms-wbt-server",
    5060: "sip",
    5432: "postgresql",
    5900: "vnc",
    5985: "winrm",
    5986: "winrm-https",
    6379: "redis",
    8080: "http-proxy",
    8443: "https-alt",
    9200: "elasticsearch",
    27017: "mongodb",
}


def guess_service_name(port: int) -> str:
    return COMMON_PORT_SERVICES.get(port, "unknown")


def _looks_like_xml_nmap(content: str) -> bool:
    head = content[:1000].lower()
    return "<?xml" in head or "<nmaprun" in head


def parse_nmap_xml(file_path: str) -> list[dict]:
    tree = ET.parse(file_path)
    root = tree.getroot()

    hosts = []

    for host in root.findall("host"):
        status_el = host.find("status")
        state = status_el.get("state") if status_el is not None else "unknown"

        addr_el = host.find("address")
        ip = addr_el.get("addr") if addr_el is not None else "unknown"

        host_data = {
            "ip": ip,
            "status": state,
            "ports": []
        }

        ports_el = host.find("ports")
        if ports_el is not None:
            for port in ports_el.findall("port"):
                state_el = port.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue

                service_el = port.find("service")
                service_name = service_el.get("name") if service_el is not None else "unknown"
                product = service_el.get("product") if service_el is not None else ""
                version = service_el.get("version") if service_el is not None else ""

                host_data["ports"].append({
                    "port": int(port.get("portid")),
                    "protocol": port.get("protocol"),
                    "service": service_name,
                    "product": product,
                    "version": version
                })

        hosts.append(host_data)

    return hosts


def parse_nmap_text(file_path: str) -> list[dict]:
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    hosts_map = {}
    current_host_ip = None
    in_port_table = False

    host_header_re = re.compile(
        r"^Nmap scan report for (?P<target>.+?)(?: \((?P<ip>[\d\.]+)\))?$"
    )

    discovered_open_re = re.compile(
        r"^Discovered open port (?P<port>\d+)\/(?P<proto>\w+) on (?P<ip>[\d\.]+)$",
        re.IGNORECASE
    )

    port_row_re = re.compile(
        r"^(?P<port>\d+)\/(?P<proto>\w+)\s+"
        r"(?P<state>\S+)\s+"
        r"(?P<service>\S+)"
        r"(?:\s+(?P<version>.+))?$"
    )

    host_down_re = re.compile(
        r"^Nmap scan report for (?P<target>.+?) \[host down\]$",
        re.IGNORECASE
    )

    def get_or_create_host(ip: str, status: str = "up") -> dict:
        if ip not in hosts_map:
            hosts_map[ip] = {
                "ip": ip,
                "status": status,
                "ports": []
            }
        else:
            if status == "up":
                hosts_map[ip]["status"] = "up"
        return hosts_map[ip]

    def add_port(ip: str, port: int, proto: str, service: str = "unknown", product: str = "", version: str = ""):
        host = get_or_create_host(ip, "up")

        for existing in host["ports"]:
            if existing["port"] == port and existing["protocol"] == proto:
                # upgrade service kalau sebelumnya unknown
                if existing["service"] == "unknown" and service != "unknown":
                    existing["service"] = service
                if not existing["product"] and product:
                    existing["product"] = product
                if not existing["version"] and version:
                    existing["version"] = version
                return

        host["ports"].append({
            "port": int(port),
            "protocol": proto,
            "service": service,
            "product": product,
            "version": version
        })

    for raw_line in lines:
        line = raw_line.rstrip("\n").strip()

        if not line:
            if in_port_table:
                in_port_table = False
            continue

        discovered_match = discovered_open_re.match(line)
        if discovered_match:
            port_num = int(discovered_match.group("port"))
            add_port(
                ip=discovered_match.group("ip"),
                port=port_num,
                proto=discovered_match.group("proto"),
                service=guess_service_name(port_num)
            )
            continue

        down_match = host_down_re.match(line)
        if down_match:
            ip = down_match.group("target").strip()
            if ip not in hosts_map:
                hosts_map[ip] = {
                    "ip": ip,
                    "status": "down",
                    "ports": []
                }
            current_host_ip = ip
            in_port_table = False
            continue

        host_match = host_header_re.match(line)
        if host_match:
            ip = host_match.group("ip")
            target = host_match.group("target").strip()

            if not ip:
                ip = target

            get_or_create_host(ip, "up")
            current_host_ip = ip
            in_port_table = False
            continue

        if line.startswith("PORT"):
            in_port_table = True
            continue

        if line.startswith("Nmap done:"):
            break

        if in_port_table and current_host_ip:
            port_match = port_row_re.match(line)
            if port_match:
                state = port_match.group("state")
                if state != "open":
                    continue

                port_num = int(port_match.group("port"))
                service_name = port_match.group("service") or guess_service_name(port_num)
                version_text = (port_match.group("version") or "").strip()

                add_port(
                    ip=current_host_ip,
                    port=port_num,
                    proto=port_match.group("proto"),
                    service=service_name,
                    product=version_text,
                    version=""
                )

    return list(hosts_map.values())


def parse_nmap_file(file_path: str) -> list[dict]:
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    if _looks_like_xml_nmap(content):
        return parse_nmap_xml(file_path)

    return parse_nmap_text(file_path)