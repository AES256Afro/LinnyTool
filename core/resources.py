"""Curated security reference links and educational resources."""

RESOURCES = {
    "Standards & Benchmarks": [
        {"name": "CIS Benchmarks", "url": "https://www.cisecurity.org/cis-benchmarks",
         "description": "Center for Internet Security configuration benchmarks"},
        {"name": "NIST SP 800-123", "url": "https://csrc.nist.gov/publications/detail/sp/800-123/final",
         "description": "Guide to General Server Security"},
        {"name": "NIST SP 800-53", "url": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
         "description": "Security and Privacy Controls"},
        {"name": "DISA STIGs", "url": "https://public.cyber.mil/stigs/",
         "description": "Security Technical Implementation Guides"},
        {"name": "PCI DSS", "url": "https://www.pcisecuritystandards.org/",
         "description": "Payment Card Industry Data Security Standard"},
    ],
    "Security Tools": [
        {"name": "OpenSCAP", "url": "https://www.open-scap.org/",
         "description": "Security Content Automation Protocol framework"},
        {"name": "Lynis", "url": "https://cisofy.com/lynis/",
         "description": "Security auditing and hardening tool"},
        {"name": "AIDE", "url": "https://aide.github.io/",
         "description": "Advanced Intrusion Detection Environment"},
        {"name": "fail2ban", "url": "https://github.com/fail2ban/fail2ban",
         "description": "Brute-force attack prevention"},
        {"name": "rkhunter", "url": "https://rkhunter.sourceforge.net/",
         "description": "Rootkit Hunter"},
        {"name": "ClamAV", "url": "https://www.clamav.net/",
         "description": "Open source antivirus engine"},
    ],
    "Hardening Guides": [
        {"name": "Linux Hardening Guide", "url": "https://madaidans-insecurities.github.io/guides/linux-hardening.html",
         "description": "Comprehensive Linux hardening guide"},
        {"name": "Ubuntu Security Guide", "url": "https://ubuntu.com/security/cis",
         "description": "CIS compliance for Ubuntu"},
        {"name": "Red Hat Security Guide", "url": "https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/index",
         "description": "RHEL security hardening documentation"},
        {"name": "Arch Linux Security", "url": "https://wiki.archlinux.org/title/Security",
         "description": "Arch Linux security wiki"},
    ],
    "Vulnerability Databases": [
        {"name": "NVD", "url": "https://nvd.nist.gov/",
         "description": "National Vulnerability Database"},
        {"name": "CISA KEV", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
         "description": "Known Exploited Vulnerabilities catalog"},
        {"name": "CVE.org", "url": "https://www.cve.org/",
         "description": "Common Vulnerabilities and Exposures"},
        {"name": "Exploit-DB", "url": "https://www.exploit-db.com/",
         "description": "Exploit database"},
    ],
    "Learning & Training": [
        {"name": "Linux Security Expert", "url": "https://linuxsecurity.expert/",
         "description": "Linux security tools and reviews"},
        {"name": "OWASP", "url": "https://owasp.org/",
         "description": "Open Web Application Security Project"},
        {"name": "SANS", "url": "https://www.sans.org/",
         "description": "SANS Institute security training"},
        {"name": "Hack The Box", "url": "https://www.hackthebox.com/",
         "description": "Cybersecurity training platform"},
    ],
}


def get_resources() -> dict:
    """Return the full resource dictionary."""
    return RESOURCES


def print_resources() -> None:
    """Print resources to terminal with formatting."""
    for category, links in RESOURCES.items():
        print(f"\n\033[1m\033[96m{category}\033[0m")
        print("-" * 50)
        for link in links:
            print(f"  \033[1m{link['name']}\033[0m")
            print(f"    {link['description']}")
            print(f"    \033[4m{link['url']}\033[0m")
        print()


def get_resources_html() -> str:
    """Generate HTML for resources section in reports."""
    import html as html_mod
    sections = []
    for category, links in RESOURCES.items():
        items = []
        for link in links:
            items.append(
                f'<li><a href="{html_mod.escape(link["url"])}" target="_blank" '
                f'style="color: #4fc3f7;">{html_mod.escape(link["name"])}</a>'
                f' &mdash; {html_mod.escape(link["description"])}</li>'
            )
        sections.append(f"<h3>{html_mod.escape(category)}</h3><ul>{''.join(items)}</ul>")
    return "\n".join(sections)
