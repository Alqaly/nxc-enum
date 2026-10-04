#!/usr/bin/env python3
"""Offline integration fixture. It never connects to a network."""
import json
import os
from pathlib import Path
import sys
import time
import zipfile

CAPS = json.loads(Path(__file__).with_name("upstream-capabilities.json").read_text())
args = sys.argv[1:]
if args == ["--version"]:
    print("fake-nxc (offline fixture)")
    raise SystemExit(1)  # Real NetExec can return 1 for --version.
proto = args[0]
if "-h" in args:
    print("usage: nxc " + proto + " target --username USER --password PASSWORD")
    for flag in CAPS["flags"][proto]:
        if os.environ.get("NXC_FAKE_OLD") and flag in ("--ous", "--groups"):
            continue
        print("  " + flag + "    fixture option")
    raise SystemExit(0)
if "-L" in args:
    print("ENUMERATION")
    for name, prop in CAPS["modules"].items():
        if proto in prop["supported_protocols"]:
            print("[*] " + name.ljust(25) + " " + prop["description"])
    raise SystemExit(0)
if "-M" in args and "--options" in args:
    name = args[args.index("-M") + 1]
    print(name + " fixture module options")
    raise SystemExit(0)
host = args[1]
ports={'smb':445,'ldap':389,'mssql':1433,'rdp':3389,'ssh':22,'ftp':21,'nfs':111,'vnc':5900,'winrm':5985,'wmi':135}
prefix = f"{proto.upper():12} {host:15} {ports[proto]:5} DC01       "
def emit(text):
    print(prefix + text)
def value(flag, default=""):
    return args[args.index(flag)+1] if flag in args else default
if '-M' in args and os.environ.get('NXC_FAKE_OPTIONS_LOG'):
    option_name = value('-M').upper()
    if len(option_name) > 11:
        option_name = option_name[:8] + '...'
    print(f"{option_name:<64} [*] fixture options initialized")
for arg in args:
    if arg.startswith("--") and arg not in CAPS["flags"][proto]:
        print("unrecognized arguments: " + arg)
        raise SystemExit(2)
if "-M" in args and value("-M") not in CAPS["modules"]:
    print("Module not found")
    raise SystemExit(2)
if os.environ.get("NXC_FAKE_CALLS"):
    with open(os.environ["NXC_FAKE_CALLS"], "a") as f:
        f.write(json.dumps(args) + "\n")
if os.environ.get('NXC_FAKE_STATE_LOG'):
    with open(os.environ['NXC_FAKE_STATE_LOG'],'a') as f:
        f.write(os.environ.get('NXC_PATH','inherited')+'\n')
names = '(name:192.0.2.10) (domain:192.0.2.10)' if os.environ.get('NXC_FAKE_IP_BANNER') else '(name:DC01) (domain:example.test)'
emit('[*] Windows Server ' + names + ' ' + ("(signing:False) (SMBv1:False)" if proto=='smb' else "(signing:None) (channel binding:Never) (NTLM:True)"))
if proto == 'smb':
    emit("(DC:True)")
username = value("-u")
secret = value("-p")
if secret and Path(secret).is_file():
    secret = Path(secret).read_text().strip()
if secret == "INVALID":
    emit(f"[-] example.test\\{username}:{secret} STATUS_LOGON_FAILURE")
    raise SystemExit(0)
if secret and os.environ.get('NXC_FAKE_NTLM_DISABLED') and '-k' not in args:
    emit('(NTLM:False) [-] STATUS_NOT_SUPPORTED')
    raise SystemExit(0)
if '-k' in args and os.environ.get('NXC_FAKE_CLOCK_SKEW'):
    emit('[-] KRB_AP_ERR_SKEW')
    raise SystemExit(0)
if os.environ.get("NXC_FAKE_GUEST_ONLY") and (proto == "ldap" or ("-u" in args and username != "Guest" and "--asreproast" not in args)):
    emit("[-] STATUS_LOGON_FAILURE")
    raise SystemExit(0)
if "-u" in args:
    if proto == 'vnc' and os.environ.get('NXC_FAKE_VNC_NO_AUTH'):
        emit('(No Auth:True)')
    else:
        emit(f"[+] example.test\\{username}:{secret}" + (" (Pwn3d!)" if secret else " (Guest)" if username == "Guest" else ""))
if os.environ.get('NXC_FAKE_ENUM_FALLBACK'):
    expected = {'smb':'Guest', 'ftp':'anonymous', 'mssql':''}.get(proto)
    inventory_call = (proto == 'smb' and ('--shares' in args or '--spider' in args)) or (proto == 'ftp' and '--ls' in args) or (proto == 'mssql' and '--database' in args)
    if inventory_call and username != expected:
        emit('[-] STATUS_ACCESS_DENIED')
        raise SystemExit(0)
if '-M' in args and value('-M') == os.environ.get('NXC_FAKE_FAIL_MODULE'):
    emit('[-] STATUS_ACCESS_DENIED')
    raise SystemExit(0)
if '-M' in args and os.environ.get('NXC_FAKE_WARNING_MODULE'):
    emit('[-] fixture diagnostic; callback not reached')
    raise SystemExit(0)
if '--ls' in args and proto == 'ftp' and os.environ.get('NXC_FAKE_FTP_TREE'):
    path = value('--ls')
    children = {'.': ['Documents', 'Documents', '..'], './Documents': ['Nested Folder'], './Documents/Nested Folder': ['Beyond Bound']}
    for name in children.get(path, []):
        emit('drwxr-xr-x 2 1000 1000 4096 Sep 30 17:29 ' + name)
    emit('lrwxrwxrwx 1 1000 1000 1 Sep 30 17:29 loop -> .')
if '--dc-list' in args and os.environ.get('NXC_FAKE_DC_LIST'):
    emit('[example.test] dc02.example.test = 192.0.2.11')
    emit('[other.test] dc01.other.test = 192.0.2.12')
    emit('[example.test] missing.example.test (A) = Host not found (NXDOMAIN)')
if proto == 'rdp' and ('--nla-screenshot' in args or '--screenshot' in args):
    screenshot = Path(os.environ.get('NXC_PATH', '.')) / 'screenshots' / ('nla.png' if '--nla-screenshot' in args else 'desktop.png')
    screenshot.parent.mkdir(parents=True, exist_ok=True)
    screenshot.write_bytes(b'OFFLINE-PNG-FIXTURE')
    emit(('NLA ' if '--nla-screenshot' in args else '') + f'Screenshot saved {screenshot}')
if "--generate-hosts-file" in args:
    Path(value("--generate-hosts-file")).write_text("192.0.2.10 dc01.example.test DC01\n")
if "--generate-krb5-file" in args:
    config = ("[libdefaults]\n default_realm = EXAMPLE.TEST\n[realms]\n EXAMPLE.TEST = { kdc = dc01.example.test }\n"
              if not os.environ.get("NXC_FAKE_BAD_KRB5") else "[realms]\n WRONG.TEST = { kdc = wrong.invalid }\n")
    Path(value("--generate-krb5-file")).write_text(config)
if os.environ.get('NXC_FAKE_KRB5_LOG') and '-k' in args:
    Path(os.environ['NXC_FAKE_KRB5_LOG']).write_text(os.environ.get('KRB5_CONFIG', 'unset'))
if "--users-export" in args:
    Path(value("--users-export")).write_text("alice\nsvc_sql\n")
if "--users" in args or "--active-users" in args:
    emit("-Username-                   -Last PW Set-        -BadPW-  -Description-")
    emit("alice                         2026-01-01 00:00:00 0        ordinary user")
    emit("svc_sql                       <never>             0        password: fixture-only")
if "--rid-brute" in args:
    emit("1101: EXAMPLE\\alice (SidTypeUser)")
    emit("1102: EXAMPLE\\svc_sql (SidTypeUser)")
    emit("1103: EXAMPLE\\DC01$ (SidTypeUser)")
    emit("512: EXAMPLE\\Domain Admins (SidTypeGroup)")
if "--shares" in args:
    emit("Share           Permissions            Remark")
    emit("-----           -----------            ------")
    emit("SYSVOL          READ                   policies")
    emit("Finance         READ,WRITE             team share")
    emit("IPC$            READ                   IPC")
    if os.environ.get('NXC_FAKE_NEW_SHARE'): emit('NewAccess       READ                   changed permissions')
if proto == "mssql" and "--database" in args and os.environ.get("NXC_FAKE_DATABASES"):
    database_arg = args[args.index("--database") + 1] if args.index("--database") + 1 < len(args) else ""
    if not database_arg:
        emit("Enumerated databases")
        emit("Database Name                  Owner")
        emit("------------------------------ -------------------------")
        emit("master                         sa")
        emit("app_data                       sa")
        emit("Total: 2 database(s)")
    else:
        emit("Tables in database: " + database_arg)
if "--get-sid" in args:
    emit("Domain SID S-1-5-21-123-456-789")
if "--query" in args and proto == "ldap":
    filt, attrs = args[args.index("--query")+1:args.index("--query")+3]
    emit("[+] Response for object: CN=Fixture,DC=example,DC=test")
    if 'schemaNamingContext' in attrs:
        emit('schemaNamingContext CN=Schema,CN=Configuration,DC=example,DC=test')
    elif 'attributeSchema' in filt:
        emit('lDAPDisplayName cascadeLegacyPwd')
    elif 'cascadeLegacyPwd' in attrs:
        emit('sAMAccountName svc_sql')
        emit('cascadeLegacyPwd Zml4dHVyZS1vbmx5')
    elif "domainDNS" in filt:
        emit("distinguishedName    DC=example,DC=test")
    elif "objectSid=" in filt:
        emit("distinguishedName    CN=Domain Admins,CN=Users,DC=example,DC=test")
    elif "objectCategory=computer" in filt:
        emit("sAMAccountName       WS01$")
        emit("dNSHostName          ws01.example.test")
    elif "description" in attrs:
        emit("sAMAccountName       svc_sql")
        emit("description          password: <script>alert('fixture')</script>")
    else:
        emit("sAMAccountName       svc_sql")
if "--spider" in args:
    emit("//192.0.2.10/SYSVOL/settings.xml [size:120 offset:20 regex:'password']")
    if os.environ.get('NXC_FAKE_XLSX') and '--content' not in args:
        emit('//192.0.2.10/SYSVOL/accounts.xlsx [size:500]')
if "--get-file" in args:
    i = args.index("--get-file")
    Path(args[i+2]).write_text("<configuration>\npassword=fixture-only\n</configuration>\n")
    if os.environ.get('NXC_FAKE_XLSX') and args[i+1].endswith('.xlsx'):
        with zipfile.ZipFile(args[i+2], 'w') as z:
            z.writestr('xl/sharedStrings.xml', '<sst><si><t>password: fixture-spreadsheet</t></si></sst>')
    if os.environ.get('NXC_FAKE_OVERSIZE'):
        Path(args[i+2]).write_bytes(b'x'*1000000)
        time.sleep(1)
if '--bloodhound' in args:
    with zipfile.ZipFile('fixture_bloodhound.zip','w') as z:
        for file in Path(__file__).with_name('bloodhound-fixture').glob('*.json'):
            z.write(file,file.name)
    emit('Compressing output into fixture_bloodhound.zip')
if "-M" in args:
    mod = value("-M")
    module_prefix = f"{mod.upper()[:8] + '...' if len(mod) > 11 else mod.upper():12} {host:15} {ports[proto]:5} DC01       "
    if not os.environ.get('NXC_FAKE_SILENT_MODULE'):
        print(module_prefix + "[*] fixture module callback executed")
    if mod == "get-network":
        folder = Path(os.environ.get("NXC_PATH", ".")) / "logs"
        folder.mkdir(parents=True, exist_ok=True)
        network_file = folder / "example.test_network_fixture.log"
        network_file.write_text("app01.example.test\nexternal.invalid\n")
        emit(f"Dumped 2 records to {network_file}")
    if mod == "adcs":
        if any(x.startswith("SERVER=") for x in args):
            emit("Published Template: Workstation")
        else:
            emit("Found PKI Enrollment Server: ca01.example.test")
            emit("Found CN: EXAMPLE-CA")
    if mod == "spider_plus":
        if any("DOWNLOAD" in x for x in args):
            raise AssertionError("Metadata mode passed a DOWNLOAD key")
        folder = Path(next(x.split("=",1)[1] for x in args if x.startswith("OUTPUT_FOLDER=")))
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "fixture.json").write_text('{"SYSVOL": {"settings.xml": {"size": 120}}}')
    if mod == "sccm" and os.environ.get("NXC_FAKE_TIMEOUT"):
        sys.stdout.flush()
        time.sleep(10)
    if mod == "spooler":
        emit("Spooler service enabled")
if "--asreproast" in args:
    Path(value("--asreproast")).write_text("FAKE-ASREP-MATERIAL-NOT-A-REAL-HASH\n")
if "--kerberoasting" in args:
    Path(value("--kerberoasting")).write_text("FAKE-TGS-MATERIAL-NOT-A-REAL-HASH\n")
