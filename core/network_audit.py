"""Network security auditing.

Enumerates listening ports, audits firewall rules, SSH configuration,
and DNS resolvers. Generates security findings based on analysis.
"""

import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from core import run_command, logger
from core.distro_detect import DistroProfile, DistroFamily


@dataclass
class ListeningPort:
    protocol: str       # tcp, udp
    address: str        # 0.0.0.0, 127.0.0.1, ::, etc.
    port: int
    process: str
    pid: int = 0


@dataclass
class NetworkFinding:
    check: str
    status: str         # Pass, Fail, Warning
    severity: str       # Critical, High, Medium, Low, Info
    description: str
    remediation: str = ""


@dataclass
class NetworkAuditResult:
    listening_ports: list[ListeningPort] = field(default_factory=list)
    firewall_type: str = "none"
    firewall_active: bool = False
    firewall_rules: str = ""
    dns_resolvers: list[str] = field(default_factory=list)
    ssh_config: dict = field(default_factory=dict)
    findings: list[NetworkFinding] = field(default_factory=list)

    @property
    def open_port_count(self) -> int:
        return len(self.listening_ports)


# Dangerous ports that should not be exposed
_DANGEROUS_PORTS = {
    21: ("FTP", "High"),
    23: ("Telnet", "Critical"),
    25: ("SMTP (unauth)", "Medium"),
    69: ("TFTP", "High"),
    111: ("RPCbind", "High"),
    135: ("MSRPC", "High"),
    139: ("NetBIOS", "High"),
    445: ("SMB", "High"),
    512: ("rexec", "Critical"),
    513: ("rlogin", "Critical"),
    514: ("rsh", "Critical"),
    1099: ("Java RMI", "High"),
    2049: ("NFS", "High"),
    3389: ("RDP", "High"),
    5900: ("VNC", "High"),
    6000: ("X11", "High"),
}

# SSH settings to check and their secure values
_SSH_SECURE_SETTINGS = {
    "permitrootlogin": ("no", "High", "Disable root SSH login"),
    "passwordauthentication": ("no", "Medium", "Disable password authentication"),
    "x11forwarding": ("no", "Low", "Disable X11 forwarding"),
    "maxauthtries": ("4", "Medium", "Limit max authentication attempts"),
    "permitemptypasswords": ("no", "Critical", "Reject empty passwords"),
    "allowtcpforwarding": ("no", "Low", "Disable TCP forwarding"),
    "clientaliveinterval": ("300", "Low", "Set client alive interval"),
    "clientalivecountmax": ("3", "Low", "Set client alive count max"),
    "logingracetime": ("60", "Low", "Set login grace time"),
    "protocol": ("2", "Critical", "Use SSH protocol 2 only"),
    "loglevel": ("VERBOSE", "Low", "Set verbose logging"),
}


def audit(profile: DistroProfile) -> NetworkAuditResult:
    """Run full network security audit."""
    result = NetworkAuditResult()

    result.listening_ports = _enumerate_ports()
    result.firewall_type, result.firewall_active, result.firewall_rules = _audit_firewall(profile)
    result.dns_resolvers = _check_dns()
    result.ssh_config = _audit_ssh()
    result.findings = _generate_findings(result)

    logger.info("Network audit: %d ports, firewall=%s(%s), %d findings",
                len(result.listening_ports), result.firewall_type,
                "active" if result.firewall_active else "inactive",
                len(result.findings))

    return result


def _enumerate_ports() -> list[ListeningPort]:
    """Parse output of 'ss -tulpn' for listening ports."""
    ports = []

    result = run_command(["ss", "-tulpn"], timeout=10)
    if result.returncode != 0:
        logger.error("Failed to enumerate ports: %s", result.stderr.strip())
        return ports

    for line in result.stdout.splitlines()[1:]:  # Skip header
        parts = line.split()
        if len(parts) < 5:
            continue
        if parts[0] not in ("tcp", "udp"):
            continue
        if parts[1] != "LISTEN" and parts[0] == "tcp":
            continue

        # Parse local address:port
        local = parts[4] if parts[0] == "tcp" else parts[4]
        addr, _, port_str = local.rpartition(":")
        try:
            port = int(port_str)
        except ValueError:
            continue

        # Parse process info: users:(("name",pid=123,fd=4))
        process = ""
        pid = 0
        proc_field = parts[-1] if len(parts) > 6 else ""
        proc_match = re.search(r'"([^"]+)",pid=(\d+)', proc_field)
        if proc_match:
            process = proc_match.group(1)
            pid = int(proc_match.group(2))

        ports.append(ListeningPort(
            protocol=parts[0],
            address=addr.strip("[]"),
            port=port,
            process=process,
            pid=pid,
        ))

    return ports


def _audit_firewall(profile: DistroProfile) -> tuple[str, bool, str]:
    """Check firewall status and rules. Returns (type, active, rules_text)."""
    # UFW
    if shutil.which("ufw"):
        result = run_command(["ufw", "status", "verbose"], timeout=10)
        if result.returncode == 0:
            active = "active" in result.stdout.lower() and "inactive" not in result.stdout.lower()
            return "ufw", active, result.stdout.strip()

    # firewalld
    if shutil.which("firewall-cmd"):
        result = run_command(["firewall-cmd", "--state"], timeout=10)
        active = result.returncode == 0 and "running" in result.stdout.lower()
        rules = ""
        if active:
            rules_result = run_command(["firewall-cmd", "--list-all"], timeout=10)
            rules = rules_result.stdout.strip()
        return "firewalld", active, rules

    # nftables
    if shutil.which("nft"):
        result = run_command(["nft", "list", "ruleset"], timeout=10)
        if result.returncode == 0:
            has_rules = bool(result.stdout.strip())
            return "nftables", has_rules, result.stdout.strip()[:2000]

    # iptables fallback
    if shutil.which("iptables"):
        result = run_command(["iptables", "-L", "-n", "-v"], timeout=10)
        if result.returncode == 0:
            lines = [l for l in result.stdout.splitlines()
                     if l.strip() and not l.startswith("Chain") and not l.startswith("pkts")]
            return "iptables", len(lines) > 0, result.stdout.strip()[:2000]

    return "none", False, ""


def _audit_ssh() -> dict:
    """Get effective SSH server configuration."""
    config = {}

    # Preferred method: sshd -T gives effective merged config
    if shutil.which("sshd"):
        result = run_command(["sshd", "-T"], timeout=10)
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                line = line.strip().lower()
                if " " in line:
                    key, _, value = line.partition(" ")
                    config[key] = value
            return config

    # Fallback: parse config files manually
    config_files = [
        Path("/etc/ssh/sshd_config"),
    ]
    # Add drop-in configs
    dropin_dir = Path("/etc/ssh/sshd_config.d")
    if dropin_dir.exists():
        config_files.extend(sorted(dropin_dir.glob("*.conf")))

    for cfg_file in config_files:
        if not cfg_file.exists():
            continue
        try:
            for line in cfg_file.read_text().splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 1)
                if len(parts) == 2:
                    config[parts[0].lower()] = parts[1].lower()
        except PermissionError:
            pass

    return config


def _check_dns() -> list[str]:
    """Get DNS resolvers from /etc/resolv.conf."""
    resolvers = []
    resolv = Path("/etc/resolv.conf")
    if resolv.exists():
        try:
            for line in resolv.read_text().splitlines():
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        resolvers.append(parts[1])
        except PermissionError:
            pass
    return resolvers


def _generate_findings(result: NetworkAuditResult) -> list[NetworkFinding]:
    """Analyze collected data and generate security findings."""
    findings = []

    # Check firewall status
    if not result.firewall_active:
        findings.append(NetworkFinding(
            check="Firewall Status",
            status="Fail",
            severity="High",
            description=f"Firewall is not active ({result.firewall_type})",
            remediation="Enable firewall: sudo ufw enable (Debian) or sudo systemctl start firewalld (RHEL)",
        ))
    else:
        findings.append(NetworkFinding(
            check="Firewall Status",
            status="Pass",
            severity="Info",
            description=f"Firewall ({result.firewall_type}) is active",
        ))

    # Check dangerous ports
    for port in result.listening_ports:
        if port.port in _DANGEROUS_PORTS:
            service, severity = _DANGEROUS_PORTS[port.port]
            # Only flag if listening on all interfaces
            if port.address in ("0.0.0.0", "::", "*", ""):
                findings.append(NetworkFinding(
                    check=f"Dangerous Port {port.port}",
                    status="Fail",
                    severity=severity,
                    description=f"{service} (port {port.port}) is listening on all interfaces (process: {port.process})",
                    remediation=f"Disable {service} or restrict to localhost",
                ))

    # Check ports listening on all interfaces
    wildcard_ports = [p for p in result.listening_ports if p.address in ("0.0.0.0", "::", "*", "")]
    if len(wildcard_ports) > 20:
        findings.append(NetworkFinding(
            check="Excessive Open Ports",
            status="Fail",
            severity="High" if len(wildcard_ports) > 50 else "Medium",
            description=f"{len(wildcard_ports)} ports listening on all interfaces",
            remediation="Review and restrict unnecessary services",
        ))

    # Check SSH configuration
    for setting, (secure_value, severity, desc) in _SSH_SECURE_SETTINGS.items():
        actual = result.ssh_config.get(setting, "")
        if not actual:
            continue

        # Special handling for numeric comparisons
        if setting in ("maxauthtries", "clientaliveinterval", "clientalivecountmax", "logingracetime"):
            try:
                actual_int = int(actual)
                secure_int = int(secure_value)
                if setting == "maxauthtries" and actual_int > secure_int:
                    findings.append(NetworkFinding(
                        check=f"SSH {setting}",
                        status="Fail",
                        severity=severity,
                        description=f"{desc}: {actual} (should be <= {secure_value})",
                        remediation=f"Set {setting} {secure_value} in sshd_config",
                    ))
                elif setting == "maxauthtries" and actual_int <= secure_int:
                    findings.append(NetworkFinding(
                        check=f"SSH {setting}", status="Pass", severity="Info",
                        description=f"{desc}: {actual} (OK)",
                    ))
                continue
            except ValueError:
                pass

        if actual != secure_value:
            findings.append(NetworkFinding(
                check=f"SSH {setting}",
                status="Fail",
                severity=severity,
                description=f"{desc}: currently '{actual}' (should be '{secure_value}')",
                remediation=f"Set {setting} {secure_value} in sshd_config",
            ))
        else:
            findings.append(NetworkFinding(
                check=f"SSH {setting}",
                status="Pass",
                severity="Info",
                description=f"{desc}: {actual} (OK)",
            ))

    return findings


def get_findings_as_dicts(result: NetworkAuditResult) -> list[dict]:
    """Convert NetworkAuditResult findings to standard dict format."""
    return [
        {
            "category": "Network Security",
            "check_name": f.check,
            "severity": f.severity,
            "status": f.status,
            "description": f.description,
            "remediation": f.remediation,
        }
        for f in result.findings
    ]
