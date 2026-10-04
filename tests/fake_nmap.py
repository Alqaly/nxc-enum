#!/usr/bin/env python3
"""Offline Nmap XML fixture: never makes a network connection."""
import sys
import os
from pathlib import Path

args = sys.argv[1:]
destination = Path(args[args.index("-oX") + 1])
target = args[-1]
share_state = "closed" if os.environ.get("NXC_FAKE_NO_SMB") else "open"
ldap_state = 'closed' if os.environ.get('NXC_FAKE_LDAPS_ONLY') else 'open'
ldaps_port = '<port protocol="tcp" portid="636"><state state="open"/><service name="ldaps"/></port>' if os.environ.get('NXC_FAKE_LDAPS_ONLY') else ''
winrm_port = '<port protocol="tcp" portid="5986"><state state="open"/><service name="https"/></port>' if os.environ.get('NXC_FAKE_WINRM_HTTPS_ONLY') else ''
rdp_state = 'open' if os.environ.get('NXC_FAKE_RDP_ONLY') else 'closed'
extra_ports = '<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port><port protocol="tcp" portid="2222"><state state="open"/><service name="ssh"/></port><port protocol="tcp" portid="6379"><state state="open"/><service name="redis"/></port>' if os.environ.get('NXC_FAKE_CUSTOM_PORTS') else ''
destination.write_text(f"""<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host><status state="up"/><address addr="{target}" addrtype="ipv4"/>
    <hostnames><hostname name="dc01.example.test" type="user"/></hostnames>
    <ports>
      <port protocol="tcp" portid="445"><state state="{share_state}"/><service name="microsoft-ds"/>
        <script id="smb2-security-mode" output="message signing enabled but not required"/></port>
      <port protocol="tcp" portid="389"><state state="{ldap_state}"/><service name="ldap" product="AD DS"/></port>
      {ldaps_port}
      {winrm_port}
      {extra_ports}
      <port protocol="tcp" portid="9999"><state state="open"/></port>
      <port protocol="tcp" portid="3389"><state state="{rdp_state}"/></port>
    </ports>
  </host>
</nmaprun>
""")
print("Offline Nmap fixture complete")
