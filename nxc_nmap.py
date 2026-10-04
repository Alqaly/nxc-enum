"""Bounded parser for Nmap's structured XML output."""
from __future__ import annotations

from pathlib import Path
import xml.etree.ElementTree as ET


def parse_nmap_xml(path: Path, expected_host: str, allowed_ports: set[int] | None, max_bytes: int = 8_000_000) -> dict:
    if not path.is_file() or path.stat().st_size > max_bytes:
        raise ValueError("Nmap XML missing or exceeds the evidence size limit")
    raw = path.read_bytes()
    if b'<!ENTITY' in raw.upper():
        raise ValueError('Nmap XML entity declarations are not accepted')
    root = ET.fromstring(raw)
    if root.tag != "nmaprun":
        raise ValueError("Not Nmap XML output")
    hosts = []
    for host in root.findall("host"):
        addresses = [a.get("addr", "") for a in host.findall("./address")]
        names = [n.get("name", "").rstrip(".") for n in host.findall("./hostnames/hostname")]
        if expected_host.casefold().rstrip(".") not in {x.casefold() for x in addresses + names}:
            continue
        ports, services, scripts = [], [], []
        for port in host.findall("./ports/port"):
            if port.get("protocol") != "tcp":
                continue
            try:
                number = int(port.get("portid", ""))
            except ValueError:
                continue
            state = port.find("./state")
            if not 1 <= number <= 65535 or (allowed_ports is not None and number not in allowed_ports) or state is None or state.get("state", "") != "open":
                continue
            ports.append(number)
            service = port.find("./service")
            if service is not None:
                services.append({"port": number, "name": service.get("name", ""),
                                 "product": service.get("product", ""), "version": service.get("version", ""),
                                 "tunnel": service.get("tunnel", "")})
            for script in port.findall("./script"):
                scripts.append({"port": number, "id": script.get("id", ""),
                                "output": script.get("output", "")[:4000]})
        for script in host.findall("./hostscript/script"):
            scripts.append({"port": None, "id": script.get("id", ""),
                            "output": script.get("output", "")[:4000]})
        hosts.append({"addresses": addresses[:8], "hostnames": names[:32],
                      "open_ports": sorted(set(ports)), "services": services,
                      "scripts": scripts[:128], "scripts_truncated": len(scripts) > 128})
    if not hosts:
        raise ValueError("Nmap XML contains no matching target")
    return hosts[0]
