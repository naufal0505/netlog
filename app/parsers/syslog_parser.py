import re
from app.normalizers.event_schema import make_event


IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

FAILED_LOGIN_RE = re.compile(
    r"failed password.*?(?:for (?:invalid user )?(?P<user>\S+))?.*?from (?P<ip>(?:\d{1,3}\.){3}\d{1,3})",
    re.IGNORECASE,
)

ACCEPTED_LOGIN_RE = re.compile(
    r"accepted password for (?P<user>\S+).*?from (?P<ip>(?:\d{1,3}\.){3}\d{1,3})",
    re.IGNORECASE,
)

INVALID_USER_RE = re.compile(
    r"invalid user (?P<user>\S+).*?from (?P<ip>(?:\d{1,3}\.){3}\d{1,3})",
    re.IGNORECASE,
)

SUDO_SESSION_RE = re.compile(
    r"sudo:.*session opened for user (?P<user>\S+)",
    re.IGNORECASE,
)

USER_CREATED_RE = re.compile(
    r"(useradd|new user|added user)",
    re.IGNORECASE,
)

FIREWALL_BLOCK_RE = re.compile(
    r"(ufw block|iptables|firewalld|denied|blocked connection|drop\b)",
    re.IGNORECASE,
)

SU_RE = re.compile(
    r"\bsu:\b|\bpam_unix\(su:",
    re.IGNORECASE,
)

SERVICE_ACTIVITY_RE = re.compile(
    r"(systemd|service started|service stopped|daemon started|daemon stopped|cron)",
    re.IGNORECASE,
)


def extract_ip(text: str) -> str:
    match = IPV4_RE.search(text)
    return match.group(0) if match else "unknown"


def parse_syslog(file_path: str) -> list[dict]:
    events = []

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            text = line.strip()
            if not text:
                continue

            host = "unknown"
            severity = "info"
            event_type = "other"
            data = {
                "message": text,
                "username": None,
                "src_ip": "unknown",
            }

            failed_match = FAILED_LOGIN_RE.search(text)
            accepted_match = ACCEPTED_LOGIN_RE.search(text)
            invalid_match = INVALID_USER_RE.search(text)
            sudo_match = SUDO_SESSION_RE.search(text)

            if failed_match:
                event_type = "auth_failure"
                severity = "warning"
                host = failed_match.group("ip") or "unknown"
                data["src_ip"] = host
                data["username"] = failed_match.groupdict().get("user")

            elif accepted_match:
                event_type = "auth_success"
                severity = "info"
                host = accepted_match.group("ip") or "unknown"
                data["src_ip"] = host
                data["username"] = accepted_match.groupdict().get("user")

            elif invalid_match:
                event_type = "invalid_user"
                severity = "warning"
                host = invalid_match.group("ip") or "unknown"
                data["src_ip"] = host
                data["username"] = invalid_match.groupdict().get("user")

            elif sudo_match:
                event_type = "sudo_session"
                severity = "info"
                data["username"] = sudo_match.groupdict().get("user")
                data["src_ip"] = extract_ip(text)
                host = data["src_ip"]

            elif USER_CREATED_RE.search(text):
                event_type = "user_creation"
                severity = "warning"
                data["src_ip"] = extract_ip(text)
                host = data["src_ip"]

            elif FIREWALL_BLOCK_RE.search(text):
                event_type = "firewall_block"
                severity = "warning"
                data["src_ip"] = extract_ip(text)
                host = data["src_ip"]

            elif SU_RE.search(text):
                event_type = "privilege_escalation"
                severity = "warning"
                data["src_ip"] = extract_ip(text)
                host = data["src_ip"]

            elif SERVICE_ACTIVITY_RE.search(text):
                event_type = "service_activity"
                severity = "info"
                data["src_ip"] = extract_ip(text)
                host = data["src_ip"]

            else:
                data["src_ip"] = extract_ip(text)
                host = data["src_ip"]

            events.append(
                make_event(
                    source="syslog",
                    event_type=event_type,
                    host=host,
                    severity=severity,
                    data=data,
                )
            )

    return events