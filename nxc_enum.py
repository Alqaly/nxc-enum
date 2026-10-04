#!/usr/bin/env python3
"""Adaptive SMB/LDAP enumeration through the installed NetExec CLI. Python 3.10+."""
from __future__ import annotations

import argparse
import collections
import concurrent.futures
import datetime as dt
import hashlib
import html
import ipaddress
import json
import os
from pathlib import Path
import posixpath
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import zipfile
import importlib.util
import math
from dataclasses import dataclass, field, replace
from nxc_analysis import Analysis, parse_share
from nxc_runtime import Scope, capture, CaptureInterrupted, verify_evidence
from nxc_nmap import parse_nmap_xml
from nxc_summary import write_summary
from nxc_live import EventStream, LiveOutput
from nxc_artifacts import inspect_artifact

VERSION = "0.17.1"
PROTOCOL_PORTS = {
    "smb": (445,), "ldap": (389, 636), "mssql": (1433,), "rdp": (3389,),
    "ssh": (22,), "ftp": (21,), "nfs": (111,), "vnc": (5900,),
    "winrm": (5985, 5986), "wmi": (135,),
}
QUICK_CHECKS = {"shares", "smb-users", "smb-user-export", "smb-policy", "interfaces",
                "ldap-users", "ldap-user-export", "groups", "computers", "dc-list",
                "domain-sid", "ldap-policy", "domain-object", "hostnames"}
ADAPTIVE_SMB = {"shares", "smb-users", "smb-user-export", "smb-policy", "rid-users",
                "interfaces", "share-index", "local-groups", "local-admins", "smb-sessions",
                "logged-on", "interactive-sessions"}
ADAPTIVE_LDAP = {"ldap-users", "ldap-user-export", "active-users", "groups", "computers",
                 "dc-list", "domain-sid", "ldap-policy", "pso", "delegation", "unconstrained",
                 "admin-count", "maq", "adcs", "subnets", "sccm", "entra", "scriptpaths",
                 "domain-object", "hostnames", "descriptions", "spns", "no-preauth",
                 "gmsa-metadata", "trusts", "rbcd", "privileged-groups", "gpos", "ou-links",
                 "domain-dacl", "directory-relationships"}
ADAPTIVE_MODULES = {
    "smb": {"enum_ca", "spooler", "webdav", "smbghost", "enum_av", "runasppl", "wcc"},
    "ldap": {"adcs", "maq", "subnets", "sccm", "entra-id", "dns-nonsecure", "get-network"},
    "mssql": {"enum_impersonate", "enum_links", "enum_logins", "mssql_cbt"},
}
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
PREFIX = re.compile(r"^[A-Z0-9_.-]+\s+\S+\s+\d+\s+\S+\s+(.*)$")


def module_callback_evidence(text, module, protocol):
    """Return true only for module logger output emitted in a host context.

    NetExec also gives ``options()`` a module-prefixed logger before any target
    connection exists. That logger prints only the padded module name. Hook
    loggers used by ``on_login()`` and ``on_admin_login()`` include the target,
    port and hostname, and occur after the protocol host banner.
    """
    clean = [ANSI.sub("", line) for line in text.splitlines()]
    module_prefix = module.upper()
    if len(module_prefix) > 11:
        module_prefix = module_prefix[:8] + "..."
    protocol_prefix = protocol.upper()
    host_context_seen = False
    host_shape = r"\s+\S+\s+\d+\s+\S+\s+"
    for line in clean:
        if re.match(r"^" + re.escape(protocol_prefix) + host_shape, line, re.I):
            host_context_seen = True
            continue
        if host_context_seen and re.match(r"^" + re.escape(module_prefix) + host_shape, line, re.I):
            return True
    return False
SECRET_HINT = re.compile(r"(?i)\b(password|passwd|pwd|secret|credential|api[_ -]?key|connectionstring|cpassword)\b")
FQDN = re.compile(r"^(?=.{1,253}$)[\w-]+(?:\.[\w-]+)+\.?$", re.ASCII)
AUTH_FAILURE = re.compile(r"STATUS_LOGON_FAILURE|STATUS_ACCOUNT_LOCKED_OUT|STATUS_PASSWORD_EXPIRED|STATUS_ACCOUNT_DISABLED|KDC_ERR_PREAUTH_FAILED|invalidCredentials|data 52e", re.I)
AUTH_DIAGNOSTICS = [
    ('clock-skew', r'KRB_AP_ERR_SKEW|clock skew'),
    ('wrong-realm', r'KDC_ERR_WRONG_REALM'),
    ('principal-unknown', r'KDC_ERR_C_PRINCIPAL_UNKNOWN|KDC_ERR_S_PRINCIPAL_UNKNOWN'),
    ('account-disabled', r'STATUS_ACCOUNT_DISABLED|KDC_ERR_CLIENT_REVOKED|data 533'),
    ('account-locked', r'STATUS_ACCOUNT_LOCKED_OUT|data 775'),
    ('password-expired', r'STATUS_PASSWORD_EXPIRED|KDC_ERR_KEY_EXPIRED|data 532'),
    ('logon-restricted', r'STATUS_LOGON_TYPE_NOT_GRANTED|STATUS_ACCOUNT_RESTRICTION'),
    ('ntlm-unavailable', r'STATUS_NOT_SUPPORTED'),
    ('invalid-credentials', r'STATUS_LOGON_FAILURE|KDC_ERR_PREAUTH_FAILED|invalidCredentials|data 52e'),
    ('name-resolution', r'Name or service not known|Temporary failure in name resolution|KDC_ERR_S_PRINCIPAL_UNKNOWN'),
]
SERVICE_PROTOCOLS = {'ssh':'ssh', 'ftp':'ftp', 'microsoft-ds':'smb', 'netbios-ssn':'smb',
                     'ldap':'ldap', 'ldaps':'ldap', 'ms-sql-s':'mssql', 'ms-wbt-server':'rdp',
                     'vnc':'vnc', 'http-wsman':'winrm', 'wsman':'winrm', 'wsmans':'winrm'}


def auth_diagnosis(text):
    return next((name for name, pattern in AUTH_DIAGNOSTICS if re.search(pattern, text, re.I)), None)


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def slug(value):
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value)[:70] + "-" + hashlib.sha256(value.encode()).hexdigest()[:8]


def payload(line):
    text = PREFIX.sub(r"\1", ANSI.sub("", line)).strip()
    return re.sub(r"^\[(?:\+|\*|-)\]\s*", "", text)


def atomic_json(path, data):
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


def read_lines(path):
    return [x.strip() for x in Path(path).read_text(encoding="utf-8").splitlines()
            if x.strip() and not x.lstrip().startswith("#")]


def valid_target(value):
    if not value or value.startswith("-") or any(c.isspace() for c in value):
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return bool(re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,252}", value))


def expand_targets(values, maximum):
    result = []
    for value in values:
        if "/" in value:
            network = ipaddress.ip_network(value, strict=False)
            if network.num_addresses > maximum + 2:
                raise ValueError(f"{value} exceeds --max-hosts={maximum}")
            hosts = map(str, network.hosts())
        else:
            if not valid_target(value):
                raise ValueError(f"Invalid target: {value!r}")
            hosts = [value.rstrip(".")]
        for host in hosts:
            if host not in result:
                result.append(host)
            if len(result) > maximum:
                raise ValueError(f"Target count exceeds --max-hosts={maximum}")
    return result


@dataclass
class Identity:
    label: str
    username: str = ""
    secret: str = field(default="", repr=False)
    kind: str = "password"
    domain: str = ""
    local: bool = False
    kerberos: bool = False
    secret_file: str = ""

    def args(self, protocol, inferred_domain):
        if self.kind == "cache":
            args = ["--use-kcache"]
            if self.username:
                args += ["-u", self.username]
        else:
            args = ["-u", self.username, "-H" if self.kind == "hash" else "-p",
                    self.secret_file or self.secret]
        domain = self.domain or inferred_domain
        if self.local and protocol == "smb":
            args += ["--local-auth"]
        elif domain:
            args += ["-d", domain]
        if self.kerberos:
            args += ["-k"]
        return args


@dataclass(frozen=True)
class Check:
    key: str
    protocol: str
    title: str
    args: tuple[str, ...] = ()
    module: str = ""
    admin: bool = False
    mode: str = "default"


def query(key, title, ldap_filter, attrs):
    return Check(key, "ldap", title, ("--query", ldap_filter, attrs))


CHECKS = [
    Check("shares", "smb", "Shares and reported access", ("--shares",)),
    Check("smb-users", "smb", "SMB/SAMR user accounts and descriptions", ("--users",)),
    Check("smb-user-export", "smb", "Export SMB user accounts", ("--users-export", "{export}")),
    Check("smb-groups", "smb", "Legacy SMB group enumeration", ("--groups",), mode="deprecated"),
    Check("smb-computers", "smb", "SMB computer accounts", ("--computers",), mode="deprecated"),
    Check("smb-policy", "smb", "Domain password policy over SMB", ("--pass-pol",)),
    Check("rid-users", "smb", "RID-to-name enumeration", ("--rid-brute", "{rid_max}")),
    Check("interfaces", "smb", "Network interfaces", ("--interfaces",)),
    Check("spooler", "smb", "Print Spooler endpoint exposure", module="spooler"),
    Check("webdav", "smb", "WebClient named-pipe exposure", module="webdav"),
    Check("share-index", "smb", "Bounded recursive share file metadata",
          ("--spider", "*", "--regex", ".*", "--depth", "{depth}", "--only-files"), mode="spider"),
    Check("disks", "smb", "Local disks", ("--disks",), admin=True),
    Check("local-groups", "smb", "Local groups", ("--local-groups",), admin=True),
    Check("local-admins", "smb", "Local Administrators membership", ("--local-groups", "Administrators"), admin=True),
    Check("smb-sessions", "smb", "Active SMB sessions", ("--smb-sessions",), admin=True),
    Check("logged-on", "smb", "Logged-on users via Workstation service", ("--loggedon-users",), admin=True),
    Check("interactive-sessions", "smb", "Interactive Windows sessions", ("--qwinsta",), admin=True),
    Check("registry-sessions", "smb", "User sessions through Remote Registry", ("--reg-sessions",), admin=True),
    Check("smb-root-dir", "smb", "Root listing of the default SMB share", ("--dir",), admin=True),
    Check("smb-snapshots", "smb", "Visible VSS snapshots", ("--list-snapshots",), admin=True),
    Check("smb-wmi-os", "smb", "Operating-system inventory over SMB/WMI",
          ("--wmi-query", "SELECT Caption,Version,BuildNumber FROM Win32_OperatingSystem"), admin=True),
    Check("processes", "smb", "Running processes", ("--tasklist",), admin=True),
    Check("smb-reg-interfaces", "smb", "Network interfaces through Remote Registry", module="enum_interfaces", admin=True),
    Check("smb-ntlmv1", "smb", "LmCompatibilityLevel and NTLMv1 policy", module="ntlmv1", admin=True),
    Check("smb-lockscreen", "smb", "Accessibility executable metadata", module="lockscreendoors", admin=True),
    Check("smb-wdigest", "smb", "WDigest registry setting", ("-o", "ACTION=check"), module="wdigest", admin=True),
    Check("smb-network-connections", "smb", "Network connections through WMI", module="get_netconnections", admin=True),
    Check("smb-dns-records", "smb", "DNS server zone records through WMI", module="enum_dns", admin=True),
    Check("ldap-users", "ldap", "Domain users and descriptions", ("--users",)),
    Check("ldap-user-export", "ldap", "Export domain user accounts", ("--users-export", "{export}")),
    Check("active-users", "ldap", "Enabled domain user accounts", ("--active-users",)),
    Check("groups", "ldap", "Domain groups", ("--groups",)),
    Check("ous", "ldap", "Organizational units", ("--ous",)),
    Check("computers", "ldap", "Computer account names", ("--computers",)),
    Check("dc-list", "ldap", "Domain controllers and trust discovery", ("--dc-list",)),
    Check("domain-sid", "ldap", "Domain SID", ("--get-sid",)),
    Check("ldap-policy", "ldap", "Domain password policy over LDAP", ("--pass-pol",)),
    Check("pso", "ldap", "Fine-grained password policies", ("--pso",)),
    Check("delegation", "ldap", "Configured delegation relationships", ("--find-delegation",)),
    Check("unconstrained", "ldap", "Accounts trusted for delegation", ("--trusted-for-delegation",)),
    Check("password-not-required", "ldap", "Accounts with PASSWD_NOTREQD", ("--password-not-required",)),
    Check("admin-count", "ldap", "Accounts with adminCount=1", ("--admin-count",)),
    Check("maq", "ldap", "Machine Account Quota", module="maq"),
    Check("adcs", "ldap", "AD CS enrollment service discovery", module="adcs"),
    Check("subnets", "ldap", "AD sites and subnets", module="subnets"),
    Check("sccm", "ldap", "SCCM infrastructure discovery", module="sccm"),
    Check("entra", "ldap", "Entra ID synchronization server discovery", module="entra-id"),
    Check("scriptpaths", "ldap", "User logon script paths", module="get-scriptpath"),
    Check("ldap-obsolete", "ldap", "Computer operating-system age inventory", module="obsolete"),
    Check("ldap-deleted", "ldap", "Deleted directory objects", ("-o", "ACTION=query"), module="tombstone"),
    query("precreated-computer-metadata", "Pre-created computer account candidates without password attempts",
          "(&(objectClass=computer)(userAccountControl=4128))", "sAMAccountName distinguishedName userAccountControl pwdLastSet"),
    query("key-credential-metadata", "Objects with registered key credentials",
          "(msDS-KeyCredentialLink=*)", "sAMAccountName distinguishedName objectClass"),
    query("domain-object", "Domain object and policy metadata", "(objectClass=domainDNS)",
          "distinguishedName objectSid ms-DS-MachineAccountQuota minPwdLength lockoutThreshold"),
    query("hostnames", "Computer DNS names and operating systems", "(objectCategory=computer)",
          "sAMAccountName dNSHostName operatingSystem operatingSystemVersion userAccountControl"),
    query("descriptions", "All user descriptions and info fields", "(&(objectCategory=person)(objectClass=user))",
          "sAMAccountName description info"),
    query("spns", "Accounts with SPNs (roastability inventory)", "(servicePrincipalName=*)",
          "sAMAccountName servicePrincipalName msDS-SupportedEncryptionTypes pwdLastSet"),
    query("no-preauth", "Enabled users without Kerberos preauthentication",
          "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
          "sAMAccountName userAccountControl pwdLastSet"),
    query("gmsa-metadata", "gMSA identities and host bindings", "(objectClass=msDS-GroupManagedServiceAccount)",
          "sAMAccountName servicePrincipalName msDS-HostServiceAccountBL msDS-ManagedPasswordInterval"),
    query("trusts", "Trust objects and flags", "(objectClass=trustedDomain)",
          "name flatName trustDirection trustType trustAttributes"),
    query("rbcd", "RBCD configuration inventory", "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
          "sAMAccountName dNSHostName msDS-AllowedToActOnBehalfOfOtherIdentity"),
    query("privileged-groups", "Protected groups and direct memberships", "(&(objectClass=group)(adminCount=1))",
          "sAMAccountName distinguishedName objectSid member"),
    query("gpos", "Group Policy objects", "(objectClass=groupPolicyContainer)",
          "displayName name gPCFileSysPath"),
    query("ou-links", "OU policy links and inheritance flags", "(objectClass=organizationalUnit)",
          "distinguishedName gPLink gPOptions"),
    Check("domain-dacl", "ldap", "Read domain-root DACL", module="daclread", mode="dacl"),
    Check("ldap-signing", "ldap", "Legacy LDAP signing/channel-binding checker", module="ldap-checker", mode="controls"),
    Check("directory-relationships", "ldap", "Directory principals and direct group relationships",
          ("--query", "(objectClass=*)", "sAMAccountName distinguishedName objectSid objectClass member memberOf primaryGroupID")),
    Check("mssql-databases", "mssql", "Databases visible to this login", ("--database",)),
    Check("mssql-rids", "mssql", "Windows principals visible through RID mapping", ("--rid-brute", "{rid_max}")),
    Check("mssql-backups", "mssql", "Database backup paths", ("--list-backups",)),
    Check("mssql-context", "mssql", "Current SQL login and server identity",
          ("--query", "SELECT SYSTEM_USER AS login_name, @@SERVERNAME AS server_name")),
    Check("mssql-priv-paths", "mssql", "SQL impersonation and role path inventory", ("-o", "ACTION=enum_priv"), module="mssql_priv"),
    Check("ftp-list", "ftp", "FTP root directory listing", ("--ls", ".")),
    Check("nfs-shares", "nfs", "NFS exports", ("--shares",)),
    Check("nfs-tree", "nfs", "Recursive NFS export metadata", ("--enum-shares", "{depth}")),
    Check("rdp-nla", "rdp", "RDP login screen and NLA state", ("--nla-screenshot",), mode="preauth"),
    Check("rdp-screenshot", "rdp", "Authenticated RDP desktop screenshot", ("--screenshot",)),
    Check("vnc-screenshot", "vnc", "VNC desktop screenshot", ("--screenshot",)),
    Check("ssh-sudo", "ssh", "SSH sudo privilege check", ("--sudo-check",)),
    Check("winrm-dir", "winrm", "WinRM directory listing", ("--dir",)),
    Check("wmi-os", "wmi", "Operating-system inventory through WMI",
          ("--wmi-query", "SELECT Caption,Version,BuildNumber,OSArchitecture FROM Win32_OperatingSystem")),
    Check("wmi-snapshots", "wmi", "Visible VSS snapshots", ("--list-snapshots",)),
]

# Modules here are reviewed as read-only discovery or credential-reading modules
# with no mandatory operator-supplied option. Installed modules outside this map
# remain visible in module-inventory.json and are never invoked implicitly.
AUTO_MODULES = {
    "smb": {
        "safe": ("bitlocker", "enum_av", "enum_ca", "enum_cve", "hyperv-host", "install_elevated",
                 "ioxidresolver", "keepass_discover", "presence", "runasppl",
                 "smbghost", "spooler", "uac", "wcc", "webdav"),
        "loot": ("aws-credentials", "gpp_autologin", "gpp_password", "gpp_privileges", "iis",
                 "powershell_history", "security-questions", "veeam", "vnc", "wifi", "winscp"),
    },
    "ldap": {
        "safe": ("adcs", "badsuccessor", "certipy-find", "dns-nonsecure", "dump-computers", "entra-id",
                 "get-desc-users", "get-info-users", "get-network", "get-scriptpath", "maq", "sccm",
                 "subnets", "user-desc", "whoami"),
        "loot": ("get-unixUserPassword", "get-userPassword", "laps"),
    },
    "mssql": {"safe": ("enum_impersonate", "enum_links", "enum_logins"), "loot": ()},
    "wmi": {"safe": ("bitlocker", "enum_dns", "get_netconnections", "ioxidresolver", "spooler"), "loot": ()},
    "ssh": {"safe": (), "loot": ("aws-credentials",)},
    "winrm": {"safe": (), "loot": ("aws-credentials", "mobaxterm", "mremoteng", "rdcman", "vnc", "wifi")},
}
AUTO_MODULES["mssql"]["safe"] += ("mssql_cbt",)

# These observations explain operational behavior without pretending that all
# enumeration is passive. Modules that can expand connections beyond the
# wrapper-managed target queue are never invoked automatically.
MODULE_SIDE_EFFECTS = {
    ("smb", "bitlocker"): "executes a remote PowerShell query when using SMB",
    ("smb", "enum_cve"): "may start Remote Registry to read patch metadata",
    ("smb", "hyperv-host"): "may start Remote Registry",
    ("smb", "install_elevated"): "may start Remote Registry",
    ("smb", "keepass_discover"): "executes remote discovery commands and may perform a broad file search",
    ("smb", "runasppl"): "may start Remote Registry",
    ("smb", "sccm-recon6"): "may start Remote Registry and connect to discovered SCCM database hosts",
    ("smb", "uac"): "may start Remote Registry",
    ("smb", "wcc"): "may start Remote Registry and writes a local module report",
}
MODULE_AUTOMATION_BLOCKERS = {
    ("smb", "sccm-recon6"): "Module can connect to discovered SCCM infrastructure outside the wrapper-managed target queue",
}


class Engine:
    def __init__(self, args):
        self.args = args
        self.out = Path(args.out).resolve()
        existed = self.out.exists()
        if existed and not args.resume:
            raise ValueError("Output directory already exists. Use --resume or choose another --out.")
        self.out.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.logs = self.out / "logs"
        self.logs.mkdir(exist_ok=True, mode=0o700)
        self.live = EventStream(self.out, display=args.live)
        self.records = []
        self.users = {}
        self.discovered = set()
        self.host_info = {}
        self.hints = []
        self.action_trace = []
        self.features = {}
        self.inferred_dns_server = None
        self.module_inventory = []
        source_audit = Path(__file__).with_name("UPSTREAM_CAPABILITY_AUDIT.json")
        self.source_modules = ({item["name"]: item for item in json.loads(source_audit.read_text())["modules"]}
                               if source_audit.is_file() else {})
        self.blocked = set()
        self.current_process = None
        self.identity = None
        self.analysis = None
        self.completed = False
        self.active_endpoint = None
        self.ticket_jobs = set()
        self.archived_records = set()
        self.simulation = os.environ.get("NXC_ENUM_SIMULATION") == "1"
        self.previous_results = json.loads(Path(args.compare).read_text(encoding="utf-8")) if args.compare else None
        self.scope = Scope(args.allow, args.exclude)
        self.scope_decisions = []
        self.last_output_limited = False
        self.last_file_limited = False
        self.last_request = 0.0
        self.nxc_state = Path(args.nxc_state).resolve() if args.nxc_state else self.out / "nxc-state"
        if not args.shared_nxc_state:
            self.nxc_state.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.temp = tempfile.TemporaryDirectory(prefix="nxc-enum-secrets-")
        if args.resume and (self.out / "results.json").exists():
            old = json.loads((self.out / "results.json").read_text())
            self.records = old.get("checks", [])
            self.users = {f"{u['domain']}\\{u['username']}": u for u in old.get("users", [])}
            self.discovered = set(old.get("discovered_hosts", []))
            self.host_info = old.get("hosts", {})
            self.hints = old.get("review_items", [])
            self.action_trace = old.get("action_trace", [])
            self.simulation = self.simulation or bool(old.get("simulation"))
            self.version = old.get("netexec_version", "not inspected")
            self.scope_decisions = old.get("scope_decisions", [])
            self.saved_run_options = old.get("run_options", {})
            if not args.analyze_only and not args.doctor:
                for record in self.records:
                    record['historical'] = True
                for hint in self.hints:
                    hint['historical'] = True
                for info in self.host_info.values():
                    info['historical'] = True
        self.cache = {r["id"]: r for r in self.records}
        if args.analyze_only and (self.out / 'capabilities.json').is_file():
            self.features = json.loads((self.out / 'capabilities.json').read_text(encoding='utf-8'))
        for previous in self.host_info.values():
            if previous.get("dc") == "True" and previous.get("kdc_address"):
                self.inferred_dns_server = previous["kdc_address"]
                break

    def redact(self, text):
        if self.identity and self.identity.secret:
            secret = self.identity.secret
            if len(secret) >= 4:
                text = text.replace(secret, "<supplied-secret>")
            else:
                text = re.sub(r"(?<!\w)" + re.escape(secret) + r"(?!\w)", "<supplied-secret>", text)
        return text

    def execute(self, cmd, timeout, on_chunk=None):
        env = os.environ.copy()
        env.update({"NO_COLOR": "1", "TERM": "dumb", "COLUMNS": "300", "PYTHONUNBUFFERED": "1"})
        generated_krb5 = self.out / "krb5.generated.conf"
        if (("-k" in cmd or "--use-kcache" in cmd) and "KRB5_CONFIG" not in env):
            try:
                digest = (hashlib.sha256(generated_krb5.read_bytes()).hexdigest()
                          if generated_krb5.is_file() and generated_krb5.stat().st_size <= 65536 else None)
            except OSError:
                digest = None
            if digest and any(info.get("krb5_validation") == "validated" and
                              info.get("krb5_sha256") == digest for info in self.host_info.values()):
                env["KRB5_CONFIG"] = str(generated_krb5)
        if not self.args.shared_nxc_state:
            self.nxc_state.mkdir(parents=True, exist_ok=True, mode=0o700)
            env["NXC_PATH"] = str(self.nxc_state)
        monitored = Path(cmd[cmd.index("--get-file")+2]) if "--get-file" in cmd else None
        text, code, expired, limit_reason, seconds = capture(cmd, self.out, env, timeout, self.args.max_log_bytes, monitored, self.args.max_file_bytes, on_chunk)
        self.last_output_limited = limit_reason == "output"
        self.last_file_limited = limit_reason == "artifact-size"
        return ANSI.sub("", text), code, expired, seconds

    @staticmethod
    def stop_process(proc):
        if proc.poll() is None:
            if os.name == "nt":
                proc.kill()
            else:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def inspect(self, protocols=None):
        if not getattr(self, "version", None) or self.version == "not inspected":
            version, code, expired, _ = self.execute([self.args.nxc, "--version"], 20)
            self.version = version.strip()
            (self.out / "netexec-version.txt").write_text(version)
        for protocol in (protocols if protocols is not None else self.args.protocols):
            if protocol in self.features:
                continue
            self.live.emit("check_started", protocol=protocol, title="Inspect installed protocol help and module list")
            help_text, _, expired, _ = self.execute([self.args.nxc, protocol, "-h"], 30)
            modules, _, mod_expired, _ = self.execute([self.args.nxc, protocol, "-L"], 30)
            if expired or "--username" not in help_text:
                self.features[protocol] = {"flags": [], "modules": {}, "available": False,
                                           "reason": "Protocol help unavailable", "module_listing_timed_out": mod_expired}
                continue
            (self.out / f"netexec-{protocol}-help.txt").write_text(help_text)
            (self.out / f"netexec-{protocol}-modules.txt").write_text(modules)
            flags = set(re.findall(r"(?<!\w)--[A-Za-z0-9_-]+|(?<!\w)-[a-zA-Z](?![\w-])", help_text))
            inventory = {}
            admin_modules = {}
            privilege = None
            for line in modules.splitlines():
                if "LOW PRIVILEGE MODULES" in line.upper():
                    privilege = False
                elif "HIGH PRIVILEGE MODULES" in line.upper():
                    privilege = True
                # NXC logger may prepend [*], and names include '-' and '_'.
                m = re.match(r"^\s*(?:\[\*\]\s*)?([\w-]+)\s{2,}(.+)", line)
                if m:
                    inventory[m[1]] = m[2].strip()
                    admin_modules[m[1]] = privilege
                    source_callbacks = self.source_modules.get(m[1], {}).get("callbacks", [])
                    if privilege is None and "on_admin_login" in source_callbacks and "on_login" not in source_callbacks:
                        admin_modules[m[1]] = True
            self.features[protocol] = {"flags": sorted(flags), "modules": inventory, "available": True,
                                       "module_requires_admin": admin_modules,
                                       "module_listing_timed_out": mod_expired}
            self.live.emit("protocol_ready", protocol=protocol, title=f"{len(flags)} flags; {len(inventory)} installed modules")
        atomic_json(self.out / "capabilities.json", self.features)
        catalog_flags = collections.defaultdict(set)
        deprecated_flags = collections.defaultdict(set)
        for check in CHECKS:
            catalog_flags[check.protocol].update(arg for arg in check.args if arg.startswith("--"))
            if check.mode == "deprecated":
                deprecated_flags[check.protocol].update(arg for arg in check.args if arg.startswith("--"))
        managed_flags = {"-u", "-p", "-H", "-k", "-M", "-o", "-L", "-d", "-t",
                         "--username", "--password", "--hash", "--domain", "--local-auth",
                         "--use-kcache", "--kdcHost", "--dns-server", "--dns-tcp", "--no-smb",
                         "--port", "--no-progress", "--threads", "--smb-timeout", "--ldap-timeout",
                         "--mssql-timeout", "--rdp-timeout", "--nfs-timeout", "--winrm-timeout",
                         "--http-timeout", "--rpc-timeout", "--ssh-timeout", "--vnc-timeout",
                         "--generate-hosts-file", "--generate-krb5-file", "--asreproast",
                         "--kerberoasting", "--bloodhound", "--collection", "--share", "--spider",
                         "--get-file", "--depth"}
        atomic_json(self.out / "flag-coverage.json", [
            {"protocol": protocol, "flag": flag,
             "classification": "deprecated-upstream" if flag in deprecated_flags[protocol] else
                               "cataloged-check" if flag in catalog_flags[protocol] else
                               "conditional-or-input" if flag in managed_flags else "manual-review",
             "note": "Installed help may expose this flag, but the current implementation reports it removed; the runner uses the supported protocol path" if flag in deprecated_flags[protocol]
                     else "Cataloged checks still require a reachable endpoint and accepted context" if flag in catalog_flags[protocol]
                     else "Input or conditional artifact option; see run settings" if flag in managed_flags
                     else "No approved automatic invocation; review installed help for prerequisites and side effects"}
            for protocol, caps in self.features.items() for flag in caps["flags"]
        ])
        option_dir = self.out / "module-options"
        option_dir.mkdir(exist_ok=True, mode=0o700)
        option_files = {}
        inspected_names = set()
        selected = ({c.module for c in CHECKS if c.module} |
                    {m for tiers in AUTO_MODULES.values() for names in tiers.values() for m in names})
        if self.args.profile == "adaptive":
            selected = ({c.module for c in CHECKS if c.module and c.key in (ADAPTIVE_SMB | ADAPTIVE_LDAP)} |
                        {m for names in ADAPTIVE_MODULES.values() for m in names})
        for proto, caps in self.features.items():
            for name in caps.get("modules", {}):
                full_option_audit = self.args.inspect_all_module_options or self.args.profile in ("standard", "deep")
                target = option_dir / (slug(proto + "-" + name) + ".txt")
                if (proto, name) in inspected_names or (not full_option_audit and name not in selected):
                    continue
                inspected_names.add((proto, name))
                if target.exists():
                    code, timed_out = 0, False
                else:
                    output, code, timed_out, _ = self.execute(
                        [self.args.nxc, proto, "-M", name, "--options"], 15)
                    target.write_text(output, encoding="utf-8")
                option_files[(proto, name)] = {"path": str(target.relative_to(self.out)), "protocol": proto,
                                      "returncode": code, "timed_out": timed_out}
                self.live.emit("module_options", protocol=proto, name=name, path=str(target.relative_to(self.out)),
                               returncode=code, timed_out=timed_out)
        covered = {(c.protocol, c.module) for c in CHECKS if c.module}
        auto_safe = {(p, m) for p, tiers in AUTO_MODULES.items() for m in tiers.get("safe", ())}
        auto_loot = {(p, m) for p, tiers in AUTO_MODULES.items() for m in tiers.get("loot", ())}
        self.module_inventory = [
            {"protocol": proto, "name": name, "description": description,
             "requires_admin": caps["module_requires_admin"].get(name),
             "side_effects": MODULE_SIDE_EFFECTS.get((proto, name), "none documented by the wrapper"),
             "automation_blocker": MODULE_AUTOMATION_BLOCKERS.get((proto, name)),
             "options": option_files.get((proto, name)),
             "options_inspected": (proto, name) in option_files,
             "coverage": "removed" if "[REMOVED]" in description.upper() else
             "check-catalog" if (proto, name) in covered else
             "automatic-safe" if (proto, name) in auto_safe else
             "automatic-loot" if (proto, name) in auto_loot else
             "manual-only-unreviewed-or-active"}
            for proto, caps in self.features.items() for name, description in caps["modules"].items()
        ]
        atomic_json(self.out / "module-inventory.json", self.module_inventory)

    def command(self, protocol, host, identity, extra):
        flags = set(self.features[protocol]["flags"])
        target = host
        if identity and (identity.kerberos or identity.kind == "cache"):
            target = self.host_info.get(host, {}).get("fqdn", host)
        args = [self.args.nxc, protocol, target]
        if "--no-progress" in flags:
            args += ["--no-progress"]
        if "--threads" in flags:
            args += ["-t", "1"]
        timeout_flag = {"smb": "--smb-timeout", "ldap": "--ldap-timeout", "mssql": "--mssql-timeout",
                        "rdp": "--rdp-timeout", "ssh": "--ssh-timeout", "nfs": "--nfs-timeout",
                        "vnc": "--vnc-timeout", "winrm": "--http-timeout", "wmi": "--rpc-timeout"}.get(protocol)
        if timeout_flag and timeout_flag in flags:
            args += [timeout_flag, str(self.args.connect_timeout)]
        dns_server = self.args.dns_server or self.inferred_dns_server
        if dns_server and "--dns-server" in flags:
            args += ["--dns-server", dns_server]
        if self.args.dns_tcp and "--dns-tcp" in flags:
            args += ["--dns-tcp"]
        kdc = self.args.kdc_host
        if not kdc and identity and (identity.kerberos or identity.kind == "cache"):
            kdc = self.host_info.get(host, {}).get("kdc_address")
        if kdc and "--kdcHost" in flags:
            args += ["--kdcHost", kdc]
        open_ports = self.host_info.get(host, {}).get("open_ports", [])
        endpoint = self.active_endpoint
        if endpoint and endpoint[0] == protocol and "--port" in flags:
            args += ["--port", str(endpoint[1])]
            if protocol == 'winrm' and '--check-proto' in flags:
                args += ['--check-proto', endpoint[2]]
        elif protocol == "ldap" and (self.args.ldaps or (636 in open_ports and 389 not in open_ports)):
            args += ["--port", "636"]
        if not endpoint and protocol == "winrm" and open_ports:
            endpoints = [(5985, "http"), (5986, "https")]
            selected = [(port, transport) for port, transport in endpoints if port in open_ports]
            if selected and "--port" in flags:
                args += ["--port", *[str(port) for port, _ in selected]]
            if selected and "--check-proto" in flags:
                args += ["--check-proto", *[transport for _, transport in selected]]
        if protocol == "ldap" and "--no-smb" in flags and self.args.no_smb_ldap:
            args += ["--no-smb"]
        if identity:
            inferred = self.host_info.get(host, {}).get("domain", self.args.domain or "")
            if identity.kind == "cache":
                if "--use-kcache" in flags:
                    args += ["--use-kcache"]
                if identity.username:
                    args += ["-u", identity.username]
            else:
                args += ["-u", identity.username]
                args += (["-H", identity.secret_file or identity.secret] if identity.kind == "hash" else
                         ["-p", identity.secret_file or identity.secret])
            domain = identity.domain or inferred
            if identity.local and "--local-auth" in flags:
                args += ["--local-auth"]
            elif domain and ("-d" in flags or "--domain" in flags):
                args += ["-d", domain]
            if identity.kerberos and "-k" in flags:
                args += ["-k"]
        return args + list(extra)

    def context_host(self, host, protocol):
        if self.active_endpoint and self.active_endpoint[0] == protocol:
            port = self.active_endpoint[1]
            if port != PROTOCOL_PORTS[protocol][0]:
                return f'{host}@{port}'
        return host

    def prepare_name_artifacts(self, host, ports):
        """Call both NetExec generators separately; upstream handles them with if/elif."""
        flags = self.features["smb"]["flags"]
        info = self.host_info[host]
        destination = self.out / "hosts" / (slug(host) + ".txt")
        destination.parent.mkdir(exist_ok=True, mode=0o700)
        destination.unlink(missing_ok=True)
        if "--generate-hosts-file" in flags:
            self.run(Check("hosts-file", "smb", "Generate suggested hosts-file entries",
                           ("--generate-hosts-file", str(destination))), host, None, force=True)
        else:
            self.run(Check("banner", "smb", "Host, domain and SMB security banner"), host, None, force=True)
        domain, short = info.get("domain", "").strip("."), info.get("hostname", "")
        if not domain or not short or domain.casefold() == short.casefold():
            self.record("bootstrap-validation", host, None, "Validate host mapping", "smb",
                        "skipped", "SMB banner did not expose a usable hostname and domain")
            return
        fqdn = short + "." + domain
        if not valid_target(short) or not valid_target(fqdn):
            self.hint("Host banner name is not usable for DNS", host, "", 0, "Invalid hostname/domain syntax")
            return
        info["fqdn"] = fqdn
        if destination.is_file():
            lines = []
            for path in sorted(destination.parent.glob("*.txt")):
                for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                    words = line.split()
                    try:
                        if len(words) >= 2 and all(valid_target(w) for w in words[1:]):
                            ipaddress.ip_address(words[0])
                            lines.append(" ".join(words))
                    except ValueError:
                        continue
            (self.out / "hosts.suggested").write_text("\n".join(dict.fromkeys(lines)) + "\n")
        if self.args.apply_hosts:
            self.install_host_mapping(host, fqdn, short)
        self.validate_host_mapping(host, fqdn)
        candidate_dc = info.get("dc") == "True" or bool({389, 636} & ports)
        if candidate_dc:
            try:
                info["kdc_address"] = str(ipaddress.ip_address(host))
            except ValueError:
                info["kdc_address"] = host
            if info.get("dc") == "True" and not self.inferred_dns_server:
                self.inferred_dns_server = info["kdc_address"]
            if "--generate-krb5-file" in flags:
                target = self.out / "krb5.generated.conf"
                target.unlink(missing_ok=True)
                info.pop("krb5_config", None)
                info.pop("krb5_sha256", None)
                self.run(Check("krb5-file", "smb", "Generate Kerberos realm configuration",
                               ("--generate-krb5-file", str(target))), host, None, force=True)
                if target.is_file() and target.stat().st_size <= 65536:
                    contents = target.read_text(encoding="utf-8", errors="replace")
                    valid = ("[realms]" in contents.lower() and domain.upper() in contents.upper() and
                             f"kdc = {fqdn}".casefold() in contents.casefold())
                    info["krb5_validation"] = "validated" if valid else "invalid realm or KDC in generated file"
                    if valid:
                        info["krb5_config"] = str(target.relative_to(self.out))
                        info["krb5_sha256"] = hashlib.sha256(target.read_bytes()).hexdigest()
                        if not self.inferred_dns_server:
                            self.inferred_dns_server = info["kdc_address"]
                else:
                    info["krb5_validation"] = "missing or oversized generated file"
                self.record("krb5-validation", host, None, "Validate generated Kerberos realm", "smb",
                            "completed" if info["krb5_validation"] == "validated" else "skipped",
                            info["krb5_validation"])
                if info["krb5_validation"] != "validated" and info.get("dc") != "True":
                    info.pop("kdc_address", None)

    def validate_host_mapping(self, host, fqdn):
        info = self.host_info[host]
        try:
            address = str(ipaddress.ip_address(host))
        except ValueError:
            info["hosts_validation"] = "hostname target; no IP mapping required"
            return
        path = Path(self.args.system_hosts_file)
        try:
            content = path.read_text(encoding="utf-8") if self.args.apply_hosts else ""
            mapped = any(line.split("#", 1)[0].split()[:2] == [address, fqdn]
                         for line in content.splitlines())
            if path == Path("/etc/hosts"):
                try:
                    mapped = address in {item[4][0] for item in socket.getaddrinfo(fqdn, None, type=socket.SOCK_STREAM)}
                except OSError:
                    mapped = False
            elif not mapped and self.args.dns_server:
                resolved = self.resolve_addresses(fqdn)
                mapped = bool(resolved and address in resolved)
            info["hosts_validation"] = "validated" if mapped else "not validated"
        except OSError as exc:
            info["hosts_validation"] = "failed: " + str(exc)
        status = "completed" if info["hosts_validation"] == "validated" else "skipped"
        self.record("bootstrap-validation", host, None, "Validate installed host mapping", "smb",
                    status, info["hosts_validation"] + "; Kerberos requires FQDN resolution")

    def install_host_mapping(self, host, fqdn, short):
        try:
            address = str(ipaddress.ip_address(host))
        except ValueError:
            return
        path = Path(self.args.system_hosts_file)
        try:
            existing = path.read_text(encoding="utf-8")
            aliases = [fqdn, short]
            domain = self.host_info[host].get("domain", "").strip(".")
            existing_names = {name.casefold() for line in existing.splitlines()
                              for name in line.split("#", 1)[0].split()[1:]}
            if (self.host_info[host].get("dc") == "True" and domain and valid_target(domain) and
                    domain.casefold() not in existing_names):
                aliases.append(domain)
            mapping = f"{address} {' '.join(aliases)} # nxc-enum\n"
            for line in existing.splitlines():
                words = line.split("#", 1)[0].split()
                if len(words) >= 2 and fqdn.casefold() in {w.casefold() for w in words[1:]} and words[0] != address:
                    self.host_info[host]["hosts_mapping"] = "conflict: existing mapping to " + words[0]
                    self.hint("Existing hosts mapping conflicts with observed address", host,
                              "hosts.suggested", 0, f"{fqdn} already maps to {words[0]}, observed {address}")
                    return
            matching = any(words and words[0] == address and
                           all(name.casefold() in {w.casefold() for w in words[1:]} for name in aliases)
                           for line in existing.splitlines()
                           if (words := line.split("#", 1)[0].split()))
            if not matching:
                with path.open("a", encoding="utf-8") as stream:
                    stream.write(("\n" if existing and not existing.endswith("\n") else "") + mapping)
            self.host_info[host]["hosts_mapping"] = "installed"
        except OSError as exc:
            self.host_info[host]["hosts_mapping"] = "failed: " + str(exc)
            self.hint("Hosts mapping could not be installed", host, "hosts.suggested", 0,
                      f"Install {address} {fqdn} or use --dns-server; {exc}")

    def missing(self, protocol, extra):
        supported = set(self.features[protocol]["flags"])
        return [x for x in extra if x.startswith("--") and x not in supported]

    def record(self, key, host, identity, title, protocol, status, reason="", cmd=None,
               text="", code=None, duration=0, metadata=None):
        label = identity.label if identity else "discovery"
        rid = f"{self.context_host(host, protocol)}|{protocol}|{label}|{key}"
        self.archive_previous(rid)
        entry = {"id": rid, "check": key, "title": title, "target": host,
                 "protocol": protocol, "identity": label, "status": status,
                 "reason": reason, "time": now(), "returncode": code, "seconds": duration,
                 "historical": False, "observation_run_id": self.live.run_id}
        if metadata:
            entry.update(metadata)
        if self.active_endpoint and self.active_endpoint[0] == protocol:
            entry['endpoint_port'] = self.active_endpoint[1]
        if cmd:
            safe = []
            for i, arg in enumerate(cmd):
                if i and cmd[i-1] in ("-p", "-H") and identity and identity.secret_file:
                    safe.append("<secret-file>")
                else:
                    safe.append(self.redact(arg))
            entry["command"] = shlex.join(safe)
            entry["request_fingerprint"] = self.request_fingerprint(cmd, identity)
            entry["netexec_version"] = getattr(self, "version", "")
            entry["artifacts"] = []
            for flag, offset in (("--users-export", 1), ("--generate-hosts-file", 1),
                                 ("--asreproast", 1), ("--kerberoasting", 1), ("--get-file", 2)):
                if flag in cmd and cmd.index(flag) + offset < len(cmd):
                    candidate = Path(cmd[cmd.index(flag) + offset]).resolve()
                    if candidate.is_relative_to(self.out) and candidate.is_file():
                        entry["artifacts"].append(str(candidate.relative_to(self.out)))
            for match in re.finditer(r"(?:NLA\s+)?Screenshot saved\s+(.+?)\s*$", text, re.I | re.M):
                raw = match[1].strip().strip("'\"")
                candidate = Path(raw)
                candidate = (candidate if candidate.is_absolute() else self.out / candidate).resolve()
                if candidate.is_relative_to(self.out) and candidate.is_file():
                    relative = str(candidate.relative_to(self.out))
                    if relative not in entry["artifacts"]:
                        entry["artifacts"].append(relative)
        if text:
            text = self.redact(text)
            logfile = self.logs / (slug(rid) + ".log")
            logfile.write_text(text, encoding="utf-8")
            entry["log"] = str(logfile.relative_to(self.out))
            self.hints = [h for h in self.hints if h["source"] != entry["log"]]
            self.extract(key, protocol, host, text, entry["log"])
        if rid in self.cache:
            self.records = [r for r in self.records if r["id"] != rid]
        self.records.append(entry)
        self.cache[rid] = entry
        print(f"[{status:20}] {host:20} {label:14} {title}", flush=True)
        self.live.emit("check_finished", target=host, protocol=protocol, check=key,
                       identity=label, status=status, reason=reason, source=entry.get("log"), seconds=duration)
        if entry.get("log"):
            partial = {"hosts": {host: self.host_info.get(host, {})}, "checks": [entry],
                       "users": [u for u in self.users.values() if entry["log"] in u["sources"]],
                       "review_items": [h for h in self.hints if h["source"] == entry["log"]]}
            observed = Analysis(self.out, partial)
            observed.collect_observations()
            self.live.update_map({"nodes": list(observed.nodes.values()),
                                  "edges": list(observed.edges.values()),
                                  "findings": list(observed.findings.values())})
        self.save(render=False)
        return entry

    def archive_previous(self, rid):
        if not self.args.resume or rid not in self.cache or rid in self.archived_records:
            return
        history = self.out / 'history' / self.live.run_id
        history.mkdir(parents=True, exist_ok=True, mode=0o700)
        logfile = self.logs / (slug(rid) + '.log')
        previous = dict(self.cache[rid])
        if logfile.is_file():
            historic_log = history / logfile.name
            shutil.copyfile(logfile, historic_log)
            previous['original_log'] = previous.get('log')
            previous['log'] = str(historic_log.relative_to(self.out))
        previous['archived_in_run'] = self.live.run_id
        atomic_json(history / (slug(rid) + '.json'), previous)
        self.archived_records.add(rid)

    def request_fingerprint(self, cmd, identity):
        normalized = list(cmd)
        for index, arg in enumerate(normalized):
            if index and normalized[index-1] in ("-p", "-H"):
                normalized[index] = "<credential>"
        options = {"command": normalized, "version": getattr(self, "version", ""),
                   "kerberos": bool(identity and identity.kerberos), "connect_timeout": self.args.connect_timeout,
                   "timeout": self.args.timeout, "max_log_bytes": self.args.max_log_bytes,
                   "state_path": str(self.nxc_state) if not self.args.shared_nxc_state else "shared"}
        if identity:
            # Resource visibility, privileges and credentials may change between runs.
            # Reuse only within this run; keep prior evidence in the history directory.
            options['access_epoch'] = self.live.run_id
        return hashlib.sha256(json.dumps(options, sort_keys=True).encode()).hexdigest()

    def run(self, check, host, identity, extra=None, force=False):
        rid = f"{self.context_host(host, check.protocol)}|{check.protocol}|{identity.label if identity else 'discovery'}|{check.key}"
        cached = self.cache.get(rid)
        extra = list(extra if extra is not None else check.args)
        missing = self.missing(check.protocol, extra)
        if missing:
            return self.record(check.key, host, identity, check.title, check.protocol,
                               "unsupported", "Installed CLI lacks " + ", ".join(missing))
        if check.module:
            modules = self.features[check.protocol]["modules"]
            description = modules.get(check.module)
            if description is None or "[REMOVED]" in description.upper():
                return self.record(check.key, host, identity, check.title, check.protocol,
                                   "unsupported", "Module absent or marked removed: " + check.module)
            extra = ["-M", check.module] + extra
        block_key = (host.casefold(), check.protocol, identity.label) if identity else None
        if block_key and block_key in self.blocked:
            return self.record(check.key, host, identity, check.title, check.protocol,
                               "skipped", "Earlier authentication failure; supplied identity stopped")
        cmd = self.command(check.protocol, host, identity, extra)
        fresh = False
        if cached:
            try:
                age = (dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(cached["time"])).total_seconds()
                maximum_age = self.args.cache_max_age_hours * 3600
                if check.key in {"logged-on", "interactive-sessions", "smb-sessions"}:
                    maximum_age = min(maximum_age, self.args.session_cache_minutes * 60)
                fresh = 0 <= age <= maximum_age
            except (KeyError, ValueError, TypeError):
                pass
        if not force and not self.args.refresh and cached and fresh and cached["status"] in ("completed", "completed-with-messages", "attempted-no-module-output") and cached.get("request_fingerprint") == self.request_fingerprint(cmd, identity):
            cached['historical'] = False
            cached['cached'] = True
            cached['reused_in_run_id'] = self.live.run_id
            print(f"[cached              ] {host:20} {check.title}", flush=True)
            return cached
        if self.args.dry_run:
            return self.record(check.key, host, identity, check.title, check.protocol, "planned", cmd=cmd)
        wait = self.args.delay - (time.monotonic() - self.last_request)
        while wait > 0:
            time.sleep(min(wait, 0.1))
            wait = self.args.delay - (time.monotonic() - self.last_request)
        self.last_request = time.monotonic()
        label = identity.label if identity else "discovery"
        self.live.emit("check_started", target=host, protocol=check.protocol, check=check.key,
                       identity=label, title=check.title)
        # Preserve old bytes before the streaming sink truncates the log.
        self.archive_previous(rid)
        live_output = LiveOutput(self.live, host, check.protocol, check.key,
                                 str((self.logs / (slug(rid) + ".log")).relative_to(self.out)), self.redact,
                                 log_path=self.logs / (slug(rid) + ".log"))
        try:
            text, code, expired, duration = self.execute(cmd, self.args.timeout, on_chunk=live_output)
        except CaptureInterrupted as exc:
            live_output.finish()
            self.record(check.key, host, identity, check.title, check.protocol, "interrupted", "Stopped by user; partial evidence retained", cmd, exc.output)
            raise
        finally:
            live_output.finish()
        if self.last_file_limited:
            status, reason = "artifact-oversize", "Transfer stopped after downloaded file exceeded --max-file-bytes"
        elif expired:
            status, reason = "timeout", "Command killed at time limit; output may be partial"
        elif self.last_output_limited:
            status, reason = "output-limited", "Command killed at --max-log-bytes; captured output is partial"
        elif "[REMOVED]" in text:
            status, reason = "unsupported", "Installed command reports that this operation was removed"
        elif auth_diagnosis(text):
            status, reason = "auth-failed", "NetExec reported an authentication failure"
            diagnosis = auth_diagnosis(text)
            reason = 'Authentication diagnostic: ' + diagnosis
            if block_key and identity.label.startswith("supplied") and diagnosis in {'invalid-credentials','account-locked','account-disabled','password-expired'}:
                self.blocked.add(block_key)
        elif re.search(r"STATUS_ACCESS_DENIED|insufficientAccessRights|access (?:is )?denied", text, re.I):
            status, reason = "denied", "Insufficient permissions; output may be partial"
        elif code != 0 or "Traceback (most recent call last)" in text or "unrecognized arguments:" in text:
            status, reason = "error", "Nonzero exit or runtime/parser error"
        elif "[-]" in text:
            status, reason = "completed-with-messages", "Inspect diagnostic messages in evidence"
        else:
            status, reason = "completed", "Command completed; absence of output is not proof of absence"
        callback_output = False
        if check.module:
            callback_output = module_callback_evidence(text, check.module, check.protocol)
            if callback_output and status in ('completed', 'completed-with-messages'):
                reason = "Module-prefixed output confirms callback execution; absence of a finding is still inconclusive"
            elif not callback_output and status in ('completed', 'completed-with-messages'):
                status = "attempted-no-module-output"
                reason = "NetExec returned successfully, but no module-prefixed output confirmed callback execution"
        entry = self.record(check.key, host, identity, check.title, check.protocol, status,
                            reason, cmd, text, code, duration,
                            metadata={'module':check.module, 'callback_confirmed':callback_output} if check.module else None)
        if auth_diagnosis(text): entry['auth_diagnostic'] = auth_diagnosis(text)
        return entry

    def logtext(self, entry):
        if not entry.get("log"):
            return ""
        path = (self.out / entry["log"]).resolve()
        if not path.is_relative_to(self.out):
            raise ValueError("A saved evidence path points outside the output directory")
        return path.read_text(encoding="utf-8")

    def add_user(self, username, domain, source):
        username = username.strip()
        if not username or username.endswith("$") or username.startswith("-") or any(c.isspace() for c in username):
            return
        if "\\" in username:
            domain, username = username.split("\\", 1)
        key = f"{domain}\\{username}"
        user = self.users.setdefault(key, {"domain": domain, "username": username, "sources": []})
        if source not in user["sources"]:
            user["sources"].append(source)

    def extract(self, key, protocol, host, text, source):
        info = self.host_info.setdefault(host, {})
        for field, pattern in [("domain", r"\(domain:([^)]*)\)"), ("hostname", r"\(name:([^)]*)\)"),
                               ("signing", r"\(signing:([^)]*)\)"), ("dc", r"\(DC:([^)]*)\)"), ("channel_binding", r"\(channel binding:([^)]*)\)"),
                               ("ntlm", r"\(NTLM:([^)]*)\)"), ("smbv1", r"\(SMBv1:([^)]*)\)"),
                               ("mssql_encryption_required", r"\(EncryptionReq:([^)]*)\)"),
                               ("vnc_no_auth", r"\(No Auth:([^)]*)\)"),
                               ("nfs_root_escape", r"\(root escape:([^)]*)\)")]:
            m = re.search(pattern, text, re.I)
            if m:
                if field in ('domain', 'hostname'):
                    value = m[1].strip()
                    try:
                        ipaddress.ip_address(value)
                        continue
                    except ValueError:
                        pass
                    if not value or not valid_target(value):
                        continue
                info[protocol + "_signing" if field == "signing" else field] = m[1]
        domain = self.args.domain or info.get("domain", "")
        for line_no, line in enumerate(text.splitlines(), 1):
            p = payload(line)
            if key == "rid-users":
                m = re.match(r"\d+:\s+(.+?)\s+\(SidTypeUser\)", p)
                if m:
                    self.add_user(m[1], domain, source)
            elif key in ("ldap-users", "smb-users", "active-users"):
                m = re.match(r"([^\s]+)\s+(?:\d{4}-\d{2}-\d{2}|<never>|0\s)", p)
                if m:
                    self.add_user(m[1], domain if protocol == "ldap" else info.get("hostname", host), source)
            elif key in ("descriptions", "spns", "no-preauth", "gmsa-metadata", "ldap-custom-values"):
                m = re.match(r"sAMAccountName\s+([^\s]+)$", p, re.I)
                if m:
                    self.add_user(m[1], domain, source)
            if key in ("hostnames", "dc-list"):
                m = re.match(r"dNSHostName\s+([^\s]+)$", p, re.I)
                if m and valid_target(m[1]):
                    self.discovered.add(m[1].rstrip("."))
                if key == "dc-list":
                    m = re.match(r"(?:\[[^\]]+\]\s+)?([^\s]+)\s+(?:(?:CNAME|PTR|NS)\s+)?=\s+(\S+)", p)
                    if m and valid_target(m[1]):
                        try:
                            ipaddress.ip_address(m[2])
                        except ValueError:
                            continue
                        self.discovered.add(m[1].rstrip("."))
            if key == "domain-object":
                m = re.match(r"distinguishedName\s+(DC=.+)$", p, re.I)
                if m:
                    info["base_dn"] = m[1]
            if key == "domain-sid":
                m = re.search(r"Domain SID\s+(S-1-5-21-[\d-]+)", p)
                if m:
                    info["sid"] = m[1]
            if (key in ("descriptions", "smb-users", "ldap-users", "active-users", "ldap-custom-values") or key.startswith("share-content-")) and SECRET_HINT.search(p) and not p.startswith(("-", "Enumerat", "Starting")):
                self.hint("Potential exposed secret; review required", host, source, line_no, p)
            if key == 'ldap-custom-values' and re.match(r'(?i)[A-Za-z0-9-]*(?:password|passwd|pwd|secret|credential)\s+\S', p):
                self.hint('Secret-like custom directory attribute; encoding and validity unverified',
                          host, source, line_no, p)
            if key in ("banner", "hosts-file") and "(signing:False)" in line:
                self.hint("SMB signing not required (relay prerequisites still need assessment)", host, source, line_no, p)
            if key in ("spooler", "webdav") and "enabled" in p.lower():
                self.hint("Service exposure; exploitability not established", host, source, line_no, p)

    def hint(self, title, host, source, line, evidence):
        item = {"title": title, "target": host, "source": source, "line": line, "evidence": evidence,
                "historical": False, "observation_run_id":self.live.run_id}
        if item not in self.hints:
            self.hints.append(item)

    def resolve_addresses(self, host):
        try:
            ipaddress.ip_address(host)
            return [host]
        except ValueError:
            pass
        dns_server = self.args.dns_server or self.inferred_dns_server
        if dns_server:
            try:
                import dns.resolver
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [dns_server]
                resolver.lifetime = self.args.connect_timeout
                return [str(r) for r in resolver.resolve(host, "A", tcp=self.args.dns_tcp)]
            except ImportError:
                dig = shutil.which("dig")
                if dig:
                    try:
                        result = subprocess.run([dig, *( ["+tcp"] if self.args.dns_tcp else [] ), "@" + dns_server, host, "A", "+short",
                                                 "+time=" + str(self.args.connect_timeout), "+tries=1"],
                                                capture_output=True, text=True, timeout=self.args.connect_timeout + 2)
                        addresses = []
                        for line in result.stdout.splitlines():
                            try:
                                addresses.append(str(ipaddress.ip_address(line.strip())))
                            except ValueError:
                                pass
                        return addresses
                    except (OSError, subprocess.TimeoutExpired):
                        return []
                # NetExec has its own resolver; bypass only the wrapper's port
                # precheck when neither optional DNS backend is available.
                return None
            except Exception:
                return []
        try:
            return list(dict.fromkeys(item[4][0] for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)))
        except OSError:
            return []

    def probe_ports(self, host):
        if self.args.dry_run or self.args.skip_port_check:
            return {port for protocol in self.args.protocols for port in self.protocol_ports(protocol)}
        if self.args.nmap:
            selected = {port for protocol in self.args.protocols for port in self.protocol_ports(protocol)}
            filename = self.out / "nmap" / (slug(host) + ".xml")
            filename.parent.mkdir(exist_ok=True, mode=0o700)
            command = [self.args.nmap_bin, "-sT", "-Pn", "-sV", "--script",
                       "default and safe and not broadcast and not external",
                       "--max-retries", "1", "-p", self.args.nmap_ports,
                       "-oX", str(filename), host]
            try:
                output, code, expired, seconds = self.execute(command, self.args.timeout)
                if code == 0 and not expired and not self.last_output_limited:
                    facts = parse_nmap_xml(filename, host, None)
                    self.host_info.setdefault(host, {})["nmap"] = facts
                    self.discovered.update(name for name in facts["hostnames"] if valid_target(name))
                    dispatch = [protocol for protocol in self.args.protocols
                                if any(port in facts["open_ports"] for port in self.protocol_ports(protocol))
                                or any(SERVICE_PROTOCOLS.get(s['name'].lower()) == protocol for s in facts['services'])]
                    self.host_info[host]['discovery_coverage'] = 'Nmap TCP ports ' + self.args.nmap_ports
                    self.action_trace.append({"time": now(), "target": host, "source": "nmap-xml",
                                              "observation": {"open_ports": facts["open_ports"],
                                                              "hostnames": facts["hostnames"]},
                                              "next_actions": [f"nxc:{protocol}" for protocol in dispatch]})
                    entry = self.record("nmap-discovery", host, None, "Nmap service and safe-default script discovery",
                                        "nmap", "completed", "Structured XML fed into protocol selection", command,
                                        output, code, seconds)
                    entry["artifacts"] = [str(filename.relative_to(self.out))]
                    return set(facts["open_ports"])
                self.record("nmap-discovery", host, None, "Nmap service and safe-default script discovery",
                            "nmap", "timeout" if expired else "error", "Nmap result incomplete; falling back to socket checks",
                            command, output, code, seconds)
            except (OSError, ValueError) as exc:
                self.record("nmap-discovery", host, None, "Nmap service and safe-default script discovery",
                            "nmap", "error", f"{type(exc).__name__}: {exc}; falling back to socket checks")
        addresses = self.resolve_addresses(host)
        if addresses is None:
            print(f"[DNS] {host}: passing DNS resolution to NetExec; port precheck skipped")
            return {port for protocol in self.args.protocols for port in self.protocol_ports(protocol)}
        self.host_info.setdefault(host, {})["resolved_addresses"] = addresses
        def probe(port):
            for address in addresses[:4]:
                try:
                    with socket.create_connection((address, port), timeout=self.args.connect_timeout):
                        return port
                except OSError:
                    pass
            return None
        ports = sorted({port for protocol in self.args.protocols for port in self.protocol_ports(protocol)})
        self.host_info.setdefault(host, {})['discovery_coverage'] = 'configured ports only; Nmap full-range discovery unavailable or disabled'
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(16, max(1, len(ports)))) as pool:
            return {p for p in pool.map(probe, ports) if p}

    def protocol_ports(self, protocol, host=None):
        endpoints = self.host_info.get(host, {}).get('protocol_endpoints', {}).get(protocol, [])
        if host is not None and endpoints:
            return tuple(e['port'] for e in endpoints)
        custom = [int(item.split(':')[1]) for item in self.args.port_map if item.split(':')[0] == protocol]
        if protocol == "ldap":
            return tuple(dict.fromkeys(((636,) if self.args.ldaps else (389, 636)) + tuple(custom)))
        return tuple(dict.fromkeys(PROTOCOL_PORTS[protocol] + tuple(custom)))

    def map_endpoints(self, host, ports):
        info = self.host_info[host]
        # Resume must describe access observed now, not a previous run's grants.
        info['access'] = {}
        info['capabilities'] = {}
        endpoints = {p: {} for p in self.args.protocols}
        services = {s['port']: s for s in info.get('nmap', {}).get('services', [])}
        for protocol in self.args.protocols:
            for port in self.protocol_ports(protocol):
                if port in ports:
                    transport = 'https' if protocol == 'winrm' and port == 5986 else 'http'
                    endpoints[protocol][port] = {'port': port, 'transport': transport, 'source': 'configured-port'}
        for port, service in services.items():
            protocol = SERVICE_PROTOCOLS.get(service['name'].lower())
            if protocol in endpoints:
                transport = 'https' if service['name'].lower() == 'wsmans' or service.get('tunnel') == 'ssl' else 'http'
                if protocol == 'ldap' and service['name'].lower() == 'ldaps': transport = 'tls'
                endpoints[protocol][port] = {'port':port, 'transport':transport, 'source':'nmap-service'}
        info['protocol_endpoints'] = {p: list(sorted(items.values(), key=lambda e:e['port'])) for p,items in endpoints.items()}
        mapped = {port for items in endpoints.values() for port in items}
        info['unsupported_services'] = [services.get(port, {'port':port, 'name':'unknown'}) for port in sorted(ports - mapped)]
        for service in info['unsupported_services']:
            self.hint('Service requires an external enumerator', host, '', 0,
                      f"TCP/{service['port']} {service.get('name','unknown')}: no selected NetExec protocol mapping")
        for script in info.get('nmap', {}).get('scripts', []):
            if script['id'] in ('clock-skew', 'ssl-date'):
                info.setdefault('clock_observations', []).append({'script':script['id'], 'output':script['output']})
        # Nmap's observed target FQDN can bootstrap non-SMB environments.
        if not info.get('fqdn'):
            names = info.get('nmap', {}).get('hostnames', [])
            fqdn = next((n for n in names if FQDN.fullmatch(n)), None)
            if fqdn:
                info.update(fqdn=fqdn, hostname=fqdn.split('.')[0], domain=self.args.domain or fqdn.split('.',1)[1])
                if self.args.apply_hosts: self.install_host_mapping(host, fqdn, info['hostname'])
                self.validate_host_mapping(host, fqdn)
        if self.args.kdc_host or self.args.dns_server:
            info.setdefault('kdc_address', self.args.kdc_host or self.args.dns_server)

    def directory_attributes(self, host, identity):
        info = self.host_info[host]
        if not info.get('base_dn') or '--query' not in self.features['ldap']['flags']:
            return
        root_check = query('ldap-schema-context', 'Directory schema naming context', '(objectClass=*)', 'schemaNamingContext')
        root = self.run(root_check, host, identity, ['--base-dn', '', *root_check.args], force=True) if '--base-dn' in self.features['ldap']['flags'] else {}
        schema = self.args.ldap_schema_dn or next((m[1] for line in self.logtext(root).splitlines()
                       if (m := re.match(r'schemaNamingContext\s+(.+)', payload(line), re.I))), None)
        attrs = list(self.args.ldap_attributes)
        if schema:
            definition = query('ldap-custom-schema', 'Custom directory attribute definitions',
                               '(&(objectClass=attributeSchema)(!(systemFlags:1.2.840.113556.1.4.803:=16)))',
                               'lDAPDisplayName attributeID systemFlags')
            entry = self.run(definition, host, identity, ['--base-dn', schema, *definition.args], force=True)
            for line in self.logtext(entry).splitlines():
                if (m := re.match(r'lDAPDisplayName\s+([A-Za-z][A-Za-z0-9-]{0,127})', payload(line))): attrs.append(m[1])
        attrs = list(dict.fromkeys(attrs))
        if not schema:
            self.hint('Schema naming context unavailable', host, root.get('log',''), 0,
                      'Selected --ldap-attribute values still queried; provide --ldap-schema-dn for schema discovery')
        if len(attrs) > self.args.max_ldap_attributes:
            self.hint('Directory attribute coverage limited', host, root.get('log',''), 0, 'Attribute count exceeds --max-ldap-attributes')
        attrs = attrs[:self.args.max_ldap_attributes]
        info['custom_attributes_requested'] = attrs
        if attrs:
            self.run(query('ldap-custom-values', 'Custom and selected directory attribute values',
                           '(&(objectCategory=person)(objectClass=user))', 'sAMAccountName distinguishedName ' + ' '.join(attrs)), host, identity)

    def auth(self, protocol, host):
        identities = []
        flags = set(self.features[protocol]["flags"])
        if self.identity and not (protocol == "ldap" and self.identity.local):
            if self.identity.kind != "hash" or "-H" in flags:
                if self.identity.kind != "cache" or "--use-kcache" in flags:
                    identities.append(self.identity)
        if not self.args.credentials_only:
            identities += [Identity("null")]
            if protocol == "smb":
                identities += [Identity("guest", self.args.guest_user)]
            elif protocol == "ftp":
                identities += [Identity("anonymous", "anonymous", "anonymous@")]
        accepted = []
        index = 0
        capabilities = []
        while index < len(identities):
            identity = identities[index]
            index += 1
            validation = self.host_info.get(host, {}).get("hosts_validation")
            if (identity.kerberos or identity.kind == "cache") and self.host_info.get(host, {}).get("fqdn") and validation not in ("validated", "hostname target; no IP mapping required"):
                self.record("auth-probe", host, identity, "Test " + identity.label + " authentication",
                            protocol, "skipped", "FQDN resolution not validated; Kerberos authentication withheld")
                continue
            check = Check("auth-probe", protocol, "Test " + identity.label + " authentication")
            entry = self.run(check, host, identity, force=True)
            text = self.logtext(entry)
            diagnosis = auth_diagnosis(text)
            info = self.host_info.get(host, {})
            if (self.args.auto_kerberos and protocol in ('smb', 'ldap', 'mssql', 'rdp', 'wmi')
                    and identity.label.startswith('supplied') and not identity.kerberos
                    and not identity.local and identity.kind != 'cache' and '-k' in flags
                    and (diagnosis == 'ntlm-unavailable' or (re.search(r'\(NTLM:\s*False\)', text, re.I) and not diagnosis))):
                usable = (info.get('fqdn') and info.get('domain') and
                          info.get('hosts_validation') in ('validated', 'hostname target; no IP mapping required') and
                          (info.get('kdc_address') or self.args.kdc_host or self.args.dns_server))
                if usable:
                    fallback = replace(identity, label=identity.label + '-kerberos', kerberos=True,
                                       domain=identity.domain or info['domain'])
                    identities.insert(index, fallback)
                    self.live.emit('auth_method_fallback', target=host, protocol=protocol,
                                   identity=identity.label, method='kerberos', reason='NTLM unavailable; names and KDC validated')
                else:
                    self.record('kerberos-fallback', host, identity, 'Kerberos fallback prerequisites', protocol,
                                'skipped', 'NTLM unavailable; validated FQDN, realm and KDC required')
            positive = any("[+]" in l and re.match(r"^[A-Z0-9_-]+\s", l) for l in text.splitlines())
            if protocol == "vnc" and re.search(r"\(No Auth:\s*True\)", text, re.I):
                positive = True
            # Guest mapping is a distinct effective identity even if a named login succeeds.
            mapped_guest = "(Guest)" in text or "Guest: True" in text
            if self.args.dry_run or (positive and entry["status"] in ("completed", "completed-with-messages")):
                elevated = '(Pwn3d!)' in text and not mapped_guest
                accepted.append((identity, elevated))
                capability = {'smb':'smb-administrator-indicator', 'winrm':'winrm-access',
                              'mssql':'sql-sysadmin-indicator', 'wmi':'wmi-execution-indicator',
                              'rdp':'rdp-access', 'ldap':'directory-authentication'}.get(protocol, protocol + '-access')
                capabilities.append({'identity': identity.label, 'effective_identity': 'Guest' if mapped_guest else identity.username or 'anonymous',
                                     'method': 'kerberos' if identity.kerberos or identity.kind == 'cache' else 'protocol-default',
                                     'capability': capability if elevated else protocol + '-authentication',
                                     'callback_elevated': elevated, 'local_admin_evidence': elevated and protocol == 'smb',
                                     'evidence': entry.get('log')})
                self.live.emit('access_capability', target=host, protocol=protocol,
                               port=self.active_endpoint[1] if self.active_endpoint else None, **capabilities[-1])
                if mapped_guest:
                    self.hint("Authentication accepted as Guest (not proof of named-account authentication)", host,
                              entry.get("log", ""), 0, identity.label + " mapped to Guest")
        endpoint = str(self.active_endpoint[1]) if self.active_endpoint else 'default'
        self.host_info[host].setdefault('capabilities', {}).setdefault(protocol, {})[endpoint] = capabilities
        return accepted

    def extra(self, check, host, identity):
        info = self.host_info.get(host, {})
        label = identity.label if identity else "anonymous"
        export = self.out / ("users-export-" + slug(self.context_host(host, check.protocol) + check.protocol + label) + ".txt")
        extra = [arg.format(export=str(export), rid_max=self.args.rid_max, depth=self.args.depth) for arg in check.args]
        if check.mode == "spider" and check.module:
            folder = self.out / "share-index" / slug(host + label)
            # Presence of ANY DOWNLOAD* key enables downloads in current upstream,
            # including DOWNLOAD_FLAG=False. Omit the key entirely for metadata-only.
            extra = ["-o", "OUTPUT_FOLDER=" + str(folder)]
        elif check.mode == "dacl":
            if not info.get("base_dn"):
                return None
            extra = ["-o", "TARGET_DN=" + info["base_dn"], "ACTION=read"]
        return extra

    def module_requires_admin(self, protocol, name):
        """Return the installed/source callback requirement for this protocol."""
        runtime = self.features.get(protocol, {}).get("module_requires_admin", {}).get(name)
        if runtime is not None:
            return bool(runtime)
        callbacks = self.source_modules.get(name, {}).get("callbacks", [])
        return "on_admin_login" in callbacks and "on_login" not in callbacks

    def import_network_names(self, entry, host):
        """Bring NetExec's DNS module output into bounded, attributable evidence."""
        if entry["status"] not in ("completed", "completed-with-messages") or self.args.dry_run:
            return
        match = re.search(r"Dumped\s+\d+\s+records\s+to\s+(.+)$", self.logtext(entry), re.M)
        if not match or self.args.shared_nxc_state:
            return
        source = Path(match[1].strip()).resolve()
        state = self.nxc_state.resolve()
        if not source.is_relative_to(state) or not source.is_file() or source.stat().st_size > 2_000_000:
            return
        names = source.read_text(encoding="utf-8", errors="replace").splitlines()[:10000]
        domain = (self.args.domain or self.host_info.get(host, {}).get("domain", "")).casefold().strip(".")
        accepted = [name.strip().rstrip(".") for name in names
                    if valid_target(name.strip()) and domain and name.strip().casefold().rstrip(".").endswith("." + domain)]
        self.discovered.update(accepted)
        self.action_trace.append({"time": now(), "target": host, "source": "nxc:ldap:get-network",
                                  "observation": {"same_domain_names": accepted},
                                  "next_actions": [f"queue-host:{name}" for name in accepted]})
        destination = self.out / "network-names" / (slug(host + entry["identity"]) + ".txt")
        destination.parent.mkdir(exist_ok=True, mode=0o700)
        destination.write_text("\n".join(accepted) + ("\n" if accepted else ""), encoding="utf-8")
        entry.setdefault("artifacts", []).append(str(destination.relative_to(self.out)))
        entry["discovered_hosts"] = len(accepted)

    def automatic_modules(self, protocol, host, sessions):
        if self.args.module_policy == "inventory":
            return
        tiers = AUTO_MODULES.get(protocol, {})
        names = list(tiers.get("safe", ()))
        if self.args.module_policy == "loot":
            names += list(tiers.get("loot", ()))
        if self.args.profile == "quick":
            names = []
        elif self.args.profile == "adaptive":
            names = [name for name in names if name in ADAPTIVE_MODULES.get(protocol, set())]
        known_checks = {c.module for c in CHECKS if c.protocol == protocol and c.module}
        for name in names:
            if name in known_checks:
                continue
            description = self.features[protocol]["modules"].get(name)
            if not description or "[REMOVED]" in description.upper():
                continue
            if (protocol, name) in MODULE_AUTOMATION_BLOCKERS:
                self.record("module-" + slug(name), host, sessions[0][0], "Module: " + name,
                            protocol, "skipped", MODULE_AUTOMATION_BLOCKERS[(protocol, name)])
                continue
            requires_admin = self.module_requires_admin(protocol, name)
            candidates = [(identity, admin) for identity, admin in sessions if admin or not requires_admin]
            check = Check("module-" + slug(name), protocol, "Module: " + name, module=name)
            if not candidates:
                self.record(check.key, host, sessions[0][0], check.title, protocol, "skipped",
                            "Requires confirmed local administrator access for this identity and target")
                continue
            for identity, _admin in candidates:
                extra = ["-o", "ONLY_HOSTS=true"] if protocol == "ldap" and name == "get-network" else None
                entry = self.run(check, host, identity, extra=extra)
                if name == "get-network":
                    self.import_network_names(entry, host)
                if entry["status"] not in ("denied", "auth-failed", "error"):
                    break

    def enumerate_host(self, host):
        self.live.emit("host_started", target=host, title="Discover protocol endpoints")
        self.host_info.setdefault(host, {})['historical'] = False
        ports = self.probe_ports(host)
        self.live.emit("ports", target=host, open_ports=sorted(ports))
        self.host_info.setdefault(host, {})["open_ports"] = sorted(ports)
        self.map_endpoints(host, ports)
        # Resolve the AD name first. A Kerberos attempt made against a bare IP
        # before this step can produce misleading authentication failures.
        if "smb" in self.args.protocols and any(p in ports for p in self.protocol_ports("smb", host)):
            self.inspect(["smb"])
            if self.features["smb"].get("available"):
                self.active_endpoint = ('smb', self.protocol_ports('smb', host)[0], 'http')
                self.prepare_name_artifacts(host, ports)
                self.active_endpoint = None
        remaining = [p for p in self.args.protocols if p != "smb" and
                     any(port in ports for port in self.protocol_ports(p, host))]
        if remaining:
            self.inspect(remaining)
        info = self.host_info[host]
        for protocol in self.args.protocols:
            endpoints = info.get('protocol_endpoints', {}).get(protocol, [])
            if not endpoints:
                self.active_endpoint = None
                self._enumerate_protocol(host, protocol, ports)
                continue
            for endpoint in endpoints:
                self.active_endpoint = (protocol, endpoint['port'], endpoint['transport'])
                if protocol == 'ldap' and endpoint['port'] not in (389, 636):
                    self.record('protocol', host, None, 'Nonstandard LDAP endpoint', protocol, 'unsupported',
                                'Reviewed NetExec LDAP connection uses fixed 389/636 ports; external enumerator required')
                    continue
                if endpoint['port'] != PROTOCOL_PORTS[protocol][0] and '--port' not in self.features.get(protocol, {}).get('flags', []):
                    self.record('endpoint', host, None, 'Detected nondefault endpoint', protocol,
                                'unsupported', 'Installed NetExec CLI lacks --port')
                    continue
                self._enumerate_protocol(host, protocol, ports)
        self.active_endpoint = None
        self.save()
        for decision in self.module_decisions():
            if decision["target"] == host:
                self.live.observation("module_decision", name=decision["module"], target=host,
                                      protocol=decision["protocol"], status=decision["status"],
                                      reason=decision["reason"], evidence=decision["evidence"])

    def _enumerate_protocol(self, host, protocol, ports):
        expected_ports = self.protocol_ports(protocol, host)
        if not any(port in ports for port in expected_ports):
            self.record("port", host, None, f"{protocol.upper()} endpoint", protocol, "unreachable",
                        "TCP/" + ",".join(map(str, expected_ports)) + " did not connect; not a finding")
            return
        if not self.features.get(protocol, {}).get("available"):
            self.record("protocol", host, None, f"{protocol.upper()} protocol", protocol, "unsupported",
                        self.features.get(protocol, {}).get("reason", "Protocol unavailable"))
            return
        # Some discovery is intentionally credential-free. Run it even when
        # no login context will be accepted, then keep it out of the
        # authenticated pass so it is never duplicated.
        for check in [c for c in CHECKS if c.protocol == protocol and c.mode == "preauth"]:
            self.run(check, host, None, self.extra(check, host, None), force=True)
        # NFS export discovery does not require a username/password exchange.
        sessions = [(None, False)] if protocol == "nfs" else self.auth(protocol, host)
        access = self.host_info[host].setdefault('access', {}).setdefault(protocol, {'endpoints':{}})
        access.setdefault('endpoints', {})
        port = str(self.active_endpoint[1]) if self.active_endpoint else 'default'
        access['endpoints'][port] = {
            "accepted_contexts": [i.label if i else "anonymous" for i, _ in sessions],
            "confirmed_admin": protocol == 'smb' and any(admin for _, admin in sessions),
            "callback_elevated": any(admin for _, admin in sessions),
        }
        access['accepted_contexts'] = list(dict.fromkeys(label for item in access['endpoints'].values() for label in item['accepted_contexts']))
        access['confirmed_admin'] = any(item['confirmed_admin'] for item in access['endpoints'].values())
        access['callback_elevated'] = any(item['callback_elevated'] for item in access['endpoints'].values())
        if not sessions:
            for check in CHECKS:
                if check.protocol == protocol and check.mode != "preauth":
                    self.record(check.key, host, None, check.title, protocol, "skipped", "No accepted authentication context")
            # AS-REP collection uses discovered usernames without testing passwords.
            if protocol == "ldap" and self.args.tickets:
                self.tickets(host, None)
            return
        # Prefer supplied credentials, then null, then guest. Fall back when a
        # stronger-looking context lacks permissions for an individual check.
        selected_contexts = {}
        for check in [c for c in CHECKS if c.protocol == protocol and c.mode != "preauth"]:
            if check.mode == "deprecated":
                self.record(check.key, host, sessions[0][0], check.title, protocol, "unsupported",
                            "Removed from the current SMB implementation; equivalent inventory is collected through LDAP")
                continue
            if self.args.profile == "quick" and check.key not in QUICK_CHECKS:
                self.record(check.key, host, sessions[0][0], check.title, protocol, "skipped", "Outside quick profile")
                continue
            if self.args.profile == "adaptive":
                selected = ADAPTIVE_SMB if protocol == "smb" else ADAPTIVE_LDAP if protocol == "ldap" else None
                if selected is not None and check.key not in selected:
                    self.record(check.key, host, sessions[0][0], check.title, protocol, "skipped", "Adaptive plan: lower-priority check; use --profile standard for exhaustive coverage")
                    continue
                if check.key == "rid-users" and self.domain_users(host):
                    self.record(check.key, host, sessions[0][0], check.title, protocol, "skipped", "Already have domain usernames; run in standard profile for independent RID coverage")
                    continue
            if check.mode == "spider" and self.args.no_spider:
                self.record(check.key, host, sessions[0][0], check.title, protocol, "skipped", "Disabled by --no-spider")
                continue
            if check.mode == "controls" and not self.args.control_checks:
                self.record(check.key, host, sessions[0][0], check.title, protocol, "skipped", "Enable --control-checks for extra authentication probes")
                continue
            candidates = [(i, admin) for i, admin in sessions if admin or not check.admin]
            if not candidates:
                self.record(check.key, host, sessions[0][0], check.title, protocol, "skipped", "Requires confirmed local administrator access")
                continue
            for identity, admin in candidates:
                extra = self.extra(check, host, identity)
                if extra is None:
                    self.record(check.key, host, identity, check.title, protocol, "skipped", "Domain base DN unavailable")
                    continue
                entry = self.run(check, host, identity, extra)
                if entry['status'] in ('completed', 'completed-with-messages', 'attempted-no-module-output'):
                    selected_contexts[check.key] = identity
                if check.key.endswith("user-export"):
                    export = Path(extra[-1])
                    if export.exists():
                        domain = self.args.domain or self.host_info.get(host, {}).get("domain", "")
                        if protocol == "smb":
                            domain = self.host_info.get(host, {}).get("hostname", host)
                        for username in read_lines(export):
                            self.add_user(username, domain, str(export.relative_to(self.out)))
                if check.key == "shares" and self.args.share_content and not self.args.download_matches:
                    self.share_content(host, identity, self.logtext(entry))
                if entry["status"] not in ("denied", "auth-failed", "error"):
                    break
        self.automatic_modules(protocol, host, sessions)
        if protocol == "mssql" and 'mssql-databases' in selected_contexts:
            self.mssql_table_inventory(host, selected_contexts['mssql-databases'])
        if protocol == "ftp" and self.args.profile in ("standard", "deep") and 'ftp-list' in selected_contexts:
            self.ftp_directory_inventory(host, selected_contexts['ftp-list'])
        if protocol == "ldap":
            primary = sessions[0][0]
            self.directory_attributes(host, primary)
            self.recursive_groups(host, primary)
            self.adcs_templates(host, primary)
            if self.args.tickets:
                self.tickets(host, primary)
            if self.args.bloodhound:
                    self.run(Check("bloodhound", "ldap", "BloodHound " + self.args.bloodhound_collection + " collection", ("--bloodhound", "--collection", self.args.bloodhound_collection)), host, primary)
        if protocol == 'smb' and self.args.download_matches and 'shares' in selected_contexts:
            identity = selected_contexts['shares']
            shares = self.cache.get(f"{self.context_host(host, 'smb')}|smb|{identity.label}|shares", {})
            self.share_content(host, identity, self.logtext(shares))

    def ftp_directory_inventory(self, host, identity):
        """Feed observed directories into bounded listing jobs; never follow symlinks."""
        initial = self.cache.get(f"{self.context_host(host, 'ftp')}|ftp|{identity.label}|ftp-list")
        if not initial:
            return
        queue = collections.deque([(".", 0, initial)])
        scheduled = {"."}
        while queue:
            parent, depth, entry = queue.popleft()
            if entry["status"] not in ("completed", "completed-with-messages"):
                continue
            for line in self.logtext(entry).splitlines():
                value = payload(line)
                unix = re.match(r"d\S{9}\s+\d+\s+\S+\s+\S+\s+\d+\s+\S+\s+\d+\s+\S+\s+(.+)$", value)
                windows = re.match(r"\d{2}-\d{2}-\d{2,4}\s+\S+\s+<DIR>\s+(.+)$", value, re.I)
                match = unix or windows
                if not match:
                    continue
                name = match[1].strip()
                if name in {".", ".."} or any(c in name for c in "/\\\r\n\0"):
                    continue
                path = posixpath.join(parent, name)
                if path in scheduled:
                    continue
                if depth >= self.args.depth or len(scheduled) >= self.args.max_directories:
                    self.hint("FTP directory inventory truncated", host, entry.get("log", ""), 0,
                              "Observed directories remain beyond --depth or --max-directories")
                    continue
                scheduled.add(path)
                self.live.emit("directory_queued", target=host, protocol="ftp", path=path,
                               discovered_from=parent)
                self.action_trace.append({"time": now(), "target": host, "source": "nxc:ftp:directory",
                                          "observation": {"parent": parent, "directory": path},
                                          "next_actions": ["ftp-list:" + path]})
                child = self.run(Check("ftp-directory-" + hashlib.sha256(path.encode()).hexdigest()[:16],
                                      "ftp", "FTP directory " + path, ("--ls", path)), host, identity)
                queue.append((path, depth + 1, child))

    def mssql_table_inventory(self, host, identity):
        entry = self.cache.get(f"{self.context_host(host, 'mssql')}|mssql|{identity.label}|mssql-databases")
        if not entry or entry["status"] not in ("completed", "completed-with-messages"):
            return
        lines = [payload(line) for line in self.logtext(entry).splitlines()]
        names = []
        listing = False
        for line in lines:
            if line == "Enumerated databases":
                listing = True
                continue
            if not listing:
                continue
            if line.startswith("Total:"):
                break
            if line.startswith(("Database Name", "----")) or not line.strip():
                continue
            name = re.split(r"\s{2,}", line.strip())[0]
            if name and len(name) <= 128 and not any(c in name for c in "\r\n\0"):
                names.append(name)
        names = list(dict.fromkeys(names))
        if len(names) > self.args.max_databases:
            self.hint("Database table inventory truncated", host, entry.get("log", ""), 0,
                      f"{len(names)} visible databases; limit {self.args.max_databases}")
        for name in names[:self.args.max_databases]:
            self.run(Check("mssql-tables-" + slug(name), "mssql", "Tables in database: " + name,
                           ("--database", name)), host, identity)

    def module_decisions(self):
        """Explain applicability for every installed module on each scanned host.

        A successful CLI invocation is evidence of execution, not proof that the
        module found a condition or that the caller has sufficient object rights.
        """
        decisions = []
        inventory = self.module_inventory
        if not inventory and (self.out / "module-inventory.json").exists():
            inventory = json.loads((self.out / "module-inventory.json").read_text(encoding="utf-8"))
        by_name = collections.defaultdict(list)
        for record in self.records:
            if not record.get('historical'):
                by_name[(record["target"], record["protocol"], record["check"])].append(record)
        catalog = {(c.protocol, c.module): c for c in CHECKS if c.module}
        for host, info in self.host_info.items():
            if "open_ports" not in info:
                continue
            for item in inventory:
                protocol, name = item["protocol"], item["name"]
                access = info.get("access", {}).get(protocol, {})
                endpoint = not info.get('historical') and any(p in info["open_ports"] for p in self.protocol_ports(protocol, host))
                check = catalog.get((protocol, name))
                key = check.key if check else "module-" + slug(name)
                matching = by_name[(host, protocol, key)]
                executed = [r for r in matching if r["status"] in
                            ("completed", "completed-with-messages", "denied", "auth-failed",
                             "error", "timeout", "output-limited", "artifact-oversize",
                             "attempted-no-module-output", "interrupted")]
                callback_confirmed = any(r.get('callback_confirmed', False) for r in executed)
                if "[REMOVED]" in item["description"].upper():
                    status, reason = "unavailable", "Installed NetExec marks this module removed"
                elif not endpoint:
                    status, reason = "not-applicable", "Protocol endpoint not reachable in this run"
                elif not access.get("accepted_contexts"):
                    status, reason = "not-applicable", "No accepted authentication context for this protocol"
                elif ((check and check.admin) or self.module_requires_admin(protocol, name)) and not access.get("callback_elevated", access.get("confirmed_admin")):
                    status, reason = "not-applicable", "Protocol administrator callback context required"
                elif (protocol, name) in MODULE_AUTOMATION_BLOCKERS:
                    status, reason = "manual-review", MODULE_AUTOMATION_BLOCKERS[(protocol, name)]
                elif executed:
                    if any(r['callback_confirmed'] and r['status'] in ('completed', 'completed-with-messages') for r in executed if 'callback_confirmed' in r):
                        status, reason = "attempted", "Module-prefixed output confirms at least one completed callback; findings are not implied"
                    elif any(r['status'] in ('timeout', 'output-limited', 'artifact-oversize', 'interrupted') for r in executed):
                        status, reason = 'attempted-partial', 'Attempt interrupted or limited; inspect partial evidence before judging coverage'
                    elif any(r['status'] in ('denied', 'auth-failed', 'error') for r in executed):
                        status, reason = 'attempted-failed', 'Attempt failed; process invocation does not confirm callback execution'
                    else:
                        status, reason = "attempted-unconfirmed", "NetExec returned without module-prefixed output; callback execution is not independently confirmed"
                elif matching and any(r["status"] == "planned" for r in matching):
                    status, reason = "planned", "Dry run only"
                elif item["coverage"] == "manual-only-unreviewed-or-active":
                    status, reason = "manual-review", "Options and side effects have not been approved for automatic execution"
                elif self.args.module_policy == "inventory":
                    status, reason = "policy-excluded", "Module policy is inventory only"
                elif item["coverage"] == "automatic-loot" and self.args.module_policy != "loot":
                    status, reason = "policy-excluded", "Credential-reading modules require --module-policy loot"
                elif self.args.profile == "quick":
                    status, reason = "profile-excluded", "Quick profile omits modules"
                elif self.args.profile == "adaptive" and name not in ADAPTIVE_MODULES.get(protocol, set()) and not (check and check.key in (ADAPTIVE_SMB | ADAPTIVE_LDAP)):
                    status, reason = "profile-excluded", "Adaptive profile prioritizes selected modules; use standard for broader coverage"
                elif matching:
                    status, reason = "not-run", matching[-1].get("reason", "See check status")
                else:
                    status, reason = "not-run", "Inspect policy and evidence before retrying"
                decisions.append({"target": host, "protocol": protocol, "module": name,
                                  "status": status, "reason": reason,
                                  "callback_confirmed": callback_confirmed,
                                  "coverage": item["coverage"],
                                  "requires_admin": self.module_requires_admin(protocol, name),
                                  "side_effects": MODULE_SIDE_EFFECTS.get((protocol, name), "none documented by the wrapper"),
                                  "evidence": [r["id"] for r in matching]})
        return decisions

    def recursive_groups(self, host, identity):
        sid = self.host_info.get(host, {}).get("sid")
        if not sid:
            return
        entry = self.run(query("domain-admin-group", "Resolve Domain Admins by SID", f"(objectSid={sid}-512)", "distinguishedName member sAMAccountName"), host, identity)
        dn = None
        for line in self.logtext(entry).splitlines():
            m = re.match(r"distinguishedName\s+(.+)", payload(line), re.I)
            if m:
                dn = m[1]
                break
        if dn:
            escaped = dn.replace("\\", r"\5c").replace("*", r"\2a").replace("(", r"\28").replace(")", r"\29").replace("\0", r"\00")
            self.run(query("recursive-domain-admins", "Transitive Domain Admins membership",
                           f"(memberOf:1.2.840.113556.1.4.1941:={escaped})", "sAMAccountName distinguishedName objectClass"), host, identity)

    def adcs_templates(self, host, identity):
        rid = f"{self.context_host(host, 'ldap')}|ldap|{identity.label}|adcs"
        entry = self.cache.get(rid, {})
        names = re.findall(r"Found CN:\s*(.+)", self.logtext(entry))
        for name in dict.fromkeys(names):
            name = name.strip()
            self.run(Check("adcs-templates-" + slug(name), "ldap", "Published templates: " + name, module="adcs"),
                     host, identity, ["-o", "SERVER=" + name])

    def share_content(self, host, identity, text):
        downloaded = 0
        for line in text.splitlines():
            p = payload(line)
            m = parse_share(p)
            if not m or "READ" not in m[1] or m[0].upper() in ("IPC$", "PRINT$"):
                continue
            share = m[0]
            entry = self.run(Check("share-content-" + slug(share), "smb", "Content search: " + share), host, identity,
                             ["--spider", share, "--content", "--regex", self.args.content_regex, "--depth", str(self.args.depth)])
            if self.args.download_matches:
                index = self.cache.get(f"{self.context_host(host, 'smb')}|smb|{identity.label}|share-index", {})
                hits = self.logtext(entry).splitlines()
                hits += [line for line in self.logtext(index).splitlines() if re.search(r'\.(?:txt|xlsx|docx|zip|pdf|pfx|p12|kdbx|psafe3|ini|config|xml|ps1|vbs|yaml|yml|bak|reg)\s+\[', line, re.I)]
                seen = set()
                for hit in hits:
                    if downloaded >= self.args.max_matches:
                        break
                    p_hit = payload(hit)
                    match = re.match(r"//[^/]+/([^/]+)/(.+?)\s+\[.*?size:\s*'?([0-9]+)'?", p_hit)
                    if not match or int(match[3]) > self.args.max_file_bytes or match[1] != share:
                        continue
                    remote = match[2].replace("/", "\\")
                    if remote in seen: continue
                    seen.add(remote)
                    if "\0" in remote or "\n" in remote or "\r" in remote:
                        continue
                    folder = self.out / "matched-files" / slug(self.context_host(host, 'smb') + identity.label)
                    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
                    suffix = Path(remote).suffix.lower()
                    suffix = suffix if re.fullmatch(r'\.[a-z0-9]{1,8}', suffix) else '.bin'
                    destination = folder / (slug(share + remote) + suffix)
                    read_entry = self.run(Check("read-match-" + slug(share + remote), "smb", "Read matched file: " + share + "\\" + remote),
                                          host, identity, ["--share", share, "--get-file", remote, str(destination)])
                    downloaded += 1
                    if destination.is_file() and destination.stat().st_size <= self.args.max_file_bytes:
                        # Excerpts are candidates, never automatically used for login.
                        inspected = inspect_artifact(destination, min(self.args.max_file_bytes, 2 * 1024 * 1024))
                        read_entry['inspection'] = {k:v for k,v in inspected.items() if k != 'sections'}
                        self.live.emit('artifact_inspected', target=host, path=str(destination.relative_to(self.out)),
                                       format=inspected['format'], status=inspected['status'])
                        for section in inspected['sections']:
                            for number, content_line in enumerate(section['text'].splitlines(), 1):
                                if SECRET_HINT.search(content_line):
                                    self.hint("Secret-like content in matched file; verify account and validity", host,
                                              str(destination.relative_to(self.out)), number,
                                              section['source'] + ': ' + self.redact(content_line[:1000]))
                    elif destination.is_file():
                        quarantine = self.out / "quarantine"
                        quarantine.mkdir(exist_ok=True, mode=0o700)
                        quarantined = quarantine / destination.name
                        destination.replace(quarantined)
                        read_entry["status"] = "artifact-oversize"
                        read_entry["reason"] = "Actual downloaded bytes exceeded --max-file-bytes; moved to quarantine, no text triage"
                        read_entry["artifacts"] = [str(quarantined.relative_to(self.out))]

    def tickets(self, host, identity):
        job = (host, identity.label if identity else 'anonymous')
        if job in self.ticket_jobs:
            return
        self.ticket_jobs.add(job)
        if identity and identity.label.startswith("supplied"):
            self.run(Check("kerberoast", "ldap", "Collect Kerberoast ticket material", ("--kerberoasting", str(self.out / ("tgs-" + slug(host) + ".txt")))), host, identity)
        if identity:
            self.run(Check("asreproast", "ldap", "Collect AS-REP material for directory-discovered users", ("--asreproast", str(self.out / ("asrep-" + slug(host) + ".txt")))), host, identity)
        else:
            users = self.domain_users(host)
            if not users:
                self.record("asreproast", host, None, "AS-REP collection", "ldap", "skipped", "No domain usernames discovered; supply --users-file if known")
                return
            userfile = self.out / ("ticket-users-" + slug(host) + ".txt")
            userfile.write_text("\n".join(users) + "\n")
            # The unauthenticated AS-REP path in NXC accepts a username file.
            ticket_identity = Identity("asrep-userlist", str(userfile), domain=self.args.domain or self.host_info.get(host, {}).get("domain", ""))
            self.run(Check("asreproast", "ldap", "Collect AS-REP material using discovered usernames", ("--asreproast", str(self.out / ("asrep-" + slug(host) + ".txt")))), host, ticket_identity)

    def domain_users(self, host):
        domain = self.args.domain or self.host_info.get(host, {}).get("domain", "")
        aliases = {domain.casefold(), domain.split(".")[0].casefold()}
        return sorted({u["username"] for u in self.users.values() if u["domain"].casefold() in aliases or u["domain"] == "supplied-list"})

    def resolve_domain(self, domain):
        # Prefer AD SRV records when dnspython is available. Fall back to the
        # supplied domain endpoint; print the reason rather than changing DNS.
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.lifetime = self.args.connect_timeout
            if self.args.dns_server:
                resolver.nameservers = [self.args.dns_server]
            records = resolver.resolve("_ldap._tcp.dc._msdcs." + domain, "SRV", tcp=self.args.dns_tcp)
            return [str(r.target).rstrip(".") for r in sorted(records, key=lambda r: (r.priority, -r.weight))][:self.args.max_hosts]
        except ImportError:
            dig = shutil.which("dig")
            if dig:
                command = [dig]
                if self.args.dns_tcp:
                    command += ["+tcp"]
                if self.args.dns_server:
                    command += ["@" + self.args.dns_server]
                command += ["_ldap._tcp.dc._msdcs." + domain, "SRV", "+short",
                            "+time=" + str(self.args.connect_timeout), "+tries=1"]
                try:
                    result = subprocess.run(command, capture_output=True, text=True, timeout=self.args.connect_timeout + 2)
                    names = [line.split()[-1].rstrip(".") for line in result.stdout.splitlines() if len(line.split()) == 4]
                    names = [name for name in names if valid_target(name)]
                    if names:
                        return list(dict.fromkeys(names))[:self.args.max_hosts]
                except (OSError, subprocess.TimeoutExpired):
                    pass
            print(f"[discovery] SRV lookup unavailable; using {domain}. Supply a DC IP/FQDN if needed.")
            return [domain]
        except Exception as exc:
            print(f"[discovery] SRV lookup unavailable ({type(exc).__name__}); using {domain}. Supply a DC IP/FQDN if needed.")
            return [domain]

    def save(self, render=True, final=False):
        decisions = self.module_decisions()
        atomic_json(self.out / "module-applicability.json", decisions)
        data = {"schema_version": 4, "wrapper_version": VERSION, "updated": now(),
                "netexec_version": getattr(self, "version", "not inspected"),
                "hosts": self.host_info, "discovered_hosts": sorted(self.discovered),
                "users": sorted(self.users.values(), key=lambda u: (u["domain"], u["username"])),
                "review_items": self.hints, "checks": self.records, "action_trace": self.action_trace,
                "scope_decisions": self.scope_decisions,
                "module_applicability_summary": dict(collections.Counter(d["status"] for d in decisions)),
                "live_events": {"path": "events.jsonl", "run_id": self.live.run_id, "map": "live-map.json"},
                "run_options": {"profile": self.args.profile, "protocols": self.args.protocols,
                                "module_policy": self.args.module_policy, "delay": self.args.delay, "allow": self.args.allow,
                                "exclude": self.args.exclude, "nxc_state": str(self.nxc_state) if not self.args.shared_nxc_state else "shared",
                                "cache_max_age_hours": self.args.cache_max_age_hours},
                "status_meaning": "completed means command completed; attempted-no-module-output means NetExec returned without module-prefixed callback evidence; neither status proves security or vulnerability"}
        if getattr(self, "simulation", False):
            data["simulation"] = True
        if self.args.analyze_only and hasattr(self, "saved_run_options"):
            data["run_options"] = self.saved_run_options
        (self.out / "users.txt").write_text("\n".join(sorted({u["username"] for u in self.users.values()})) + "\n")
        (self.out / "discovered-hosts.txt").write_text("\n".join(sorted(self.discovered)) + "\n")
        atomic_json(self.out / "action-trace.json", self.action_trace)
        if render:
            self.analysis = Analysis(self.out, data, self.args.import_bloodhound,
                                     self.args.path_from, self.args.path_to, self.args.path_depth,
                                     self.args.max_paths, self.args.review_file, self.args.import_loot,
                                     paths_per_goal=self.args.paths_per_goal).build()
            data["analysis"] = self.analysis
            self.live.update_map(self.analysis, final=final, replace=True)
            summary = write_summary(self.out, data, decisions)
            data["summary"] = {"path": "summary.md", "hosts_scanned": summary["hosts_scanned"],
                               "findings": len(summary["findings"])}
            if self.args.compare:
                old = self.previous_results.get("analysis", {})
                delta = {}
                for name in ("findings", "paths"):
                    before = {item["id"]: item for item in old.get(name, [])}
                    after = {item["id"]: item for item in self.analysis.get(name, [])}
                    delta[name] = {"new_ids": sorted(after.keys() - before.keys()),
                                   "no_longer_observed_ids": sorted(before.keys() - after.keys()),
                                   "retained_ids": sorted(after.keys() & before.keys())}
                delta["meaning"] = "No longer observed does not mean remediated; compare scope, authentication and coverage."
                atomic_json(self.out / "delta.json", delta)
                data["comparison"] = delta
            self.report(data)
        atomic_json(self.out / "results.json", data)

    def report(self, data):
        esc = lambda x: html.escape(str(x), quote=True)
        counts = collections.Counter('historical' if r.get('historical') else r['status'] for r in self.records)
        rows, md = [], ["# NetExec enumeration results", "", f"Updated: {data['updated']}", "",
                        "Completed checks are observations, not automatic vulnerability verdicts.", "",
                        "| Target | Identity | Check | Status | Evidence |", "|---|---|---|---|---|"]
        for r in self.records:
            log = r.get("log", "")
            state = 'historical' if r.get('historical') else r['status']
            context = ('Previous observation: ' + r['status']) if r.get('historical') else 'Cached prior observation' if r.get('cached') else 'Current run'
            evidence = esc(self.logtext(r)[-18000:]) if log else ""
            rows.append(f"<tr data-status='{esc(state)}'><td>{esc(r['target'])}<br><small>{esc(r['identity'])}</small></td><td>{esc(r['title'])}</td><td>{esc(state)}<br><small>{esc(context)} · {esc(r.get('time', ''))}<br>{esc(r.get('reason',''))}</small></td><td><details><summary>Command and evidence</summary><pre>{esc(r.get('command',''))}</pre><a href='{esc(log)}'>Full log</a><pre>{evidence}</pre></details></td></tr>")
            clean = lambda v: str(v).replace("|", r"\|").replace("\n", " ")
            md.append("| " + " | ".join(map(clean, [r["target"], r["identity"], r["title"], state, f"[{log}]({log})" if log else r.get("reason", "")])) + " |")
        reviews = "".join(f"<li><b>{esc(h['title'])}</b> — {esc(h['target'])}<pre>{esc(h['evidence'])}</pre><a href='{esc(h['source'])}'>Evidence, line {h['line']}</a></li>" for h in self.hints if not h.get('historical'))
        options = "".join(f"<option>{esc(k)}</option>" for k in sorted(counts))
        page = """<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>NetExec enumeration results</title><style>body{font:15px system-ui;background:#111827;color:#e5e7eb;max-width:1400px;margin:32px auto;padding:0 20px}h1{font-size:28px}a{color:#93c5fd}table{width:100%;border-collapse:collapse}td,th{padding:12px;border-bottom:1px solid #374151;text-align:left;vertical-align:top}small{color:#aebacf}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#0b1120;padding:12px;border-radius:6px;max-height:450px;overflow:auto}input,select{background:#1f2937;color:white;border:1px solid #64748b;padding:10px;margin:10px 8px 20px 0}summary{cursor:pointer}li{margin-bottom:20px}.stats{padding:16px;background:#1f2937;border-radius:8px}</style>"""
        page += f"<h1>NetExec enumeration results</h1><p>{esc(data['updated'])} · wrapper {VERSION}</p><p><a href='summary.md'>Start with the scan summary →</a> · <a href='analysis.html'>Attack paths, ranked findings and loot →</a></p><p class=stats>{esc(dict(counts))} · {len(self.users)} account records · {len(self.discovered)} discovered hosts</p><p>Completed = command completed. No output does not prove a secure configuration. Review prerequisites before treating an observation as an exploitable finding.</p><input id=q placeholder='Filter host, check, identity…'><select id=s><option value=''>All statuses</option>{options}</select><h2>Items to review</h2><ul>{reviews or '<li>No automated review items extracted. Inspect the evidence.</li>'}</ul><h2>Checklist</h2><table><thead><tr><th>Target / identity</th><th>Check</th><th>Status</th><th>Evidence</th></tr></thead><tbody>{''.join(rows)}</tbody></table>"
        if data.get("simulation"):
            page = page.replace("<h1>", "<p class=stats><b>SIMULATED REPORT — offline fixture, no real network scan</b></p><h1>", 1)
        md[2:2] = ["[Attack paths, findings and loot](analysis.html)", ""]
        page += """<script>const q=document.getElementById('q'),s=document.getElementById('s');function filter(){for(const row of document.querySelectorAll('tbody tr'))row.hidden=!(row.textContent.toLowerCase().includes(q.value.toLowerCase())&&(!s.value||row.dataset.status===s.value));}q.addEventListener('input',filter);s.addEventListener('change',filter);</script></html>"""
        (self.out / "report.html").write_text(page, encoding="utf-8")
        (self.out / "report.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    def main(self):
        if self.args.analyze_only:
            self.save(final=True)
            self.completed = True
            print(f"Analysis: {self.out / 'analysis.html'}")
            return 0
        if self.args.doctor or self.args.dry_run:
            self.inspect()
        a = self.args
        if a.doctor:
            cache_name = os.environ.get("KRB5CCNAME", "")
            cache_path = cache_name.removeprefix("FILE:")
            diagnostic = {"python": sys.version.split()[0], "platform": sys.platform,
                "netexec_version": self.version, "netexec_executable": a.nxc,
                "state_directory": str(self.nxc_state) if not a.shared_nxc_state else "inherited NetExec state",
                "dnspython_available": importlib.util.find_spec("dns") is not None, "dig_available": bool(shutil.which("dig")),
                "kerberos_cache_configured": bool(cache_name), "kerberos_file_cache_exists": bool(cache_path and Path(cache_path).is_file()),
                "missing_base_flags": {p: sorted({f for c in CHECKS if c.protocol == p for f in c.args if f.startswith('--')} - set(self.features[p]['flags'])) for p in self.features},
                "note": "Local inspection only. DNS, clock synchronization, credentials and target access are not validated."}
            atomic_json(self.out / "doctor.json", diagnostic)
            print(json.dumps(diagnostic, indent=2))
            return 0
        if a.username or a.use_kcache:
            kind = "cache" if a.use_kcache else "hash" if a.hash_file else "password"
            secret = ""
            if kind == "hash":
                secret = Path(a.hash_file).read_text().strip()
                if not re.fullmatch(r"(?:[a-fA-F0-9]{32}:)?[a-fA-F0-9]{32}", secret):
                    raise ValueError("--hash-file must contain one NT hash or LM:NT pair")
            elif kind == "password":
                if a.password_file:
                    secret = Path(a.password_file).read_text(encoding="utf-8").rstrip("\r\n")
                elif a.password_env:
                    if a.password_env not in os.environ:
                        raise ValueError(f"Environment variable {a.password_env} is not set")
                    secret = os.environ[a.password_env]
                else:
                    raise ValueError("Supply --password-file or --password-env with -u; the runner does not prompt. An empty password file explicitly supplies a blank password.")
                if "\n" in secret or "\r" in secret:
                    raise ValueError("Password input must contain exactly one password")
            identity_label = "supplied:" + (a.domain or "inferred") + "\\" + (a.username or "kerberos-cache") + ":" + kind + (":local" if a.local_auth else "")
            identity = Identity(identity_label, a.username or "", secret, kind, a.domain or "", a.local_auth, a.kerberos)
            if secret:
                secretfile = Path(self.temp.name) / "credential.txt"
                secretfile.write_text(secret + "\n", encoding="utf-8")
                secretfile.chmod(0o600)
                identity.secret_file = str(secretfile)
            self.identity = identity
        if a.users_file:
            for user in read_lines(a.users_file):
                self.add_user(user, a.domain or "supplied-list", "supplied-users-file")
        values = list(a.targets)
        if a.targets_file:
            values += read_lines(a.targets_file)
        if not values and a.domain:
            values = [a.domain] if a.dry_run else self.resolve_domain(a.domain)
        targets = expand_targets(values, a.max_hosts)
        if not targets:
            raise ValueError("Supply an IP, hostname, CIDR, --targets-file, or --domain")
        (self.out / "targets.txt").write_text("\n".join(targets) + "\n")
        queue, visited = collections.deque(targets), set()
        self.live.emit("run_started", targets=targets, protocols=a.protocols, profile=a.profile,
                       resume=a.resume, output=str(self.out))
        scheduled = {h.casefold() for h in targets}
        scanned = []
        while queue:
            host = queue.popleft()
            visited.add(host.casefold())
            addresses = []
            if self.scope.exclude or self.scope.allow:
                if self.scope.matches(host, self.scope.exclude):
                    permitted, why = False, "excluded target name"
                else:
                    addresses = (self.resolve_addresses(host) or []) if not a.dry_run and any(not isinstance(m, str) for m in self.scope._rules.values()) else []
                    permitted, why = self.scope.decision(host, addresses)
                self.scope_decisions.append({"target": host, "addresses": addresses, "permitted": permitted, "reason": why, "time": now()})
                if not permitted:
                    self.record("scope", host, None, "Target selection", "smb", "excluded", why)
                    continue
            scanned.append(host)
            self.enumerate_host(host)
            if a.follow_discovery:
                domain = a.domain or next((i.get("domain") for i in self.host_info.values() if i.get("domain")), "")
                suffix = "." + domain.casefold() if domain else ""
                for name in sorted(self.discovered):
                    if not suffix or not name.casefold().endswith(suffix) or name.casefold() in scheduled:
                        continue
                    if len(scheduled) >= a.max_hosts:
                        self.hint("Discovery truncated at --max-hosts", "discovery", "discovered-hosts.txt", 0, "Remaining names are inventory only")
                        break
                    scheduled.add(name.casefold())
                    queue.append(name)
                    self.live.emit("host_queued", target=name, title="Discovered same-domain host", discovered_from=host)
        (self.out / "scanned-targets.txt").write_text("\n".join(scanned) + "\n")
        self.save(final=True)
        self.completed = True
        self.live.emit("run_finished", hosts=len(scanned), users=len(self.users),
                       report="report.html", summary="summary.md")
        print(f"\nSummary: {self.out / 'summary.md'}\nReport:  {self.out / 'report.html'}\nJSON:    {self.out / 'results.json'}")
        return 0


def parser():
    p = argparse.ArgumentParser(description="Autonomous protocol-wide NetExec enumeration and evidence collection; no interactive prompts.")
    p.add_argument("targets", nargs="*", help="IP, hostname, or CIDR (space-separated)")
    p.add_argument("--targets-file", help="One target/CIDR per line")
    p.add_argument("-d", "--domain", help="AD DNS domain; SRV discovery when no target is supplied")
    p.add_argument("-u", "--username", help="One supplied username")
    auth = p.add_mutually_exclusive_group()
    auth.add_argument("--password-file", help="File containing exactly one password")
    auth.add_argument("--password-env", help="Environment variable containing one password")
    auth.add_argument("--hash-file", help="File containing one NT hash or LM:NT pair")
    auth.add_argument("--use-kcache", action="store_true", help="Use existing KRB5CCNAME")
    p.add_argument("--local-auth", action="store_true")
    p.add_argument("-k", "--kerberos", action="store_true")
    p.add_argument("--dns-server", help="AD DNS server IP passed to NetExec")
    p.add_argument("--dns-tcp", action="store_true", help="Use TCP DNS in installed NetExec and the optional local resolver")
    p.add_argument("--kdc-host", help="KDC hostname/IP passed as --kdcHost when supported")
    p.add_argument("--ldaps", action="store_true", help="Use LDAP port 636")
    p.add_argument("--no-smb-ldap", action="store_true", help="Pass --no-smb if installed version supports it")
    p.add_argument("--users-file", help="Seed username inventory for optional AS-REP collection")
    p.add_argument("--credentials-only", action="store_true", help="Skip null/Guest tests")
    p.add_argument("--guest-user", default="Guest", help="Guest account name for the blank-password test")
    p.add_argument("--follow-discovery", action=argparse.BooleanOptionalAction, default=True,
                   help="Recursively enumerate discovered computer DNS names in the selected domain (default: enabled)")
    p.add_argument("--protocols", default=",".join(PROTOCOL_PORTS), metavar="LIST",
                   help="Comma-separated protocols; default: all installed NetExec protocols")
    p.add_argument("--module-policy", choices=("inventory", "safe", "loot"), default="safe",
                   help="Inventory modules only, run reviewed read-only modules, or include credential-reading modules")
    p.add_argument("--allow", action="append", default=[], metavar="CIDR_OR_NAME", help="Allow IP/CIDR/hostname/glob rules for wrapper-managed targets (repeatable)")
    p.add_argument("--exclude", action="append", default=[], metavar="CIDR_OR_NAME", help="Exclude IP/CIDR/hostname/glob rules from wrapper-managed targets (repeatable)")
    p.add_argument("--profile", choices=("quick", "adaptive", "standard", "deep"), default="standard", help="Standard runs all cataloged enumeration checks; adaptive and quick are opt-in reductions; deep adds sensitive collection")
    p.add_argument("--apply-hosts", action=argparse.BooleanOptionalAction, default=True,
                   help="Install and validate observed IP/FQDN mappings in the system hosts file (default: enabled)")
    p.add_argument("--system-hosts-file", default="/etc/hosts", help=argparse.SUPPRESS)
    p.add_argument("--inspect-all-module-options", action="store_true", help="Also query --options for every installed module, including modules never run automatically")
    p.add_argument("--live", action=argparse.BooleanOptionalAction, default=True,
                   help="Show target output and discoveries as they arrive (default: enabled); events.jsonl is always retained")
    p.add_argument("--delay", type=float, default=0, help="Minimum seconds between wrapper NetExec target invocations")
    p.add_argument("--share-content", action="store_true", help="Search readable share contents for secret-like patterns")
    p.add_argument("--download-matches", action="store_true", help="Read bounded files matched by --share-content and extract review excerpts")
    p.add_argument("--max-matches", type=int, default=20, help="Maximum matched-file reads per identity/host share-search pass")
    p.add_argument("--max-file-bytes", type=int, default=262144, help="Maximum reported file size eligible for matched-file reads")
    p.add_argument("--content-regex", default=r"(?i)(password|passwd|pwd|secret|credential|api[_-]?key|connectionstring|cpassword)")
    p.add_argument("--depth", type=int, default=3, help="Share-content recursion depth")
    p.add_argument("--no-spider", action="store_true", help="Skip recursive share metadata inventory")
    p.add_argument("--tickets", action="store_true", help="Collect AS-REP/TGS material using supported NetExec options")
    p.add_argument("--bloodhound", action="store_true", help="Collect DCOnly BloodHound data as an additional artifact")
    p.add_argument("--bloodhound-collection", default="DCOnly", choices=("DCOnly", "All", "Group,ACL,ObjectProps", "Group,LocalAdmin,Session,ACL,ObjectProps"), help="Collection methods when --bloodhound is selected; All includes host enumeration")
    p.add_argument("--import-bloodhound", action="append", default=[], metavar="JSON_OR_ZIP", help="Import existing collector-format BloodHound JSON/ZIP (repeatable)")
    p.add_argument("--import-loot", action="append", default=[], metavar="FILE", help="Retain a supplied evidence file in the local loot inventory (repeatable, max 64 MiB/file)")
    p.add_argument("--path-from", action="append", default=[], metavar="PRINCIPAL", help="Path start name or SID; defaults to an accepted supplied SMB identity (repeatable)")
    p.add_argument("--path-to", action="append", default=[], metavar="PRINCIPAL", help="Path goal name or SID; defaults to observed high-value groups/objects (repeatable)")
    p.add_argument("--path-depth", type=int, default=6, help="Maximum candidate relationship-path hops")
    p.add_argument("--max-paths", type=int, default=40, help="Maximum candidate paths exported")
    p.add_argument("--paths-per-goal", type=int, default=2, help="Maximum alternative simple paths for each start/goal pair")
    p.add_argument("--analyze-only", action="store_true", help="Rebuild graph, loot and reports from --out; no NetExec execution or network requests")
    p.add_argument("--verify-evidence", action="store_true", help="Compare saved loot hashes without replacing results or manifest; no NetExec needed")
    p.add_argument("--review-file", help="JSON object keyed by finding ID with status and note fields")
    p.add_argument("--compare", metavar="PREVIOUS_RESULTS_JSON", help="Export finding/path changes relative to a previous results.json")
    p.add_argument("--control-checks", action="store_true", help="Run legacy LDAP signing checker if present and not removed")
    p.add_argument("--rid-max", type=int, default=4000)
    p.add_argument("--max-hosts", type=int, default=256)
    p.add_argument("--max-databases", type=int, default=64, help="Maximum visible SQL databases to follow into table inventories per host")
    p.add_argument("--max-directories", type=int, default=64, help="Maximum FTP directory listings per host and accepted identity")
    p.add_argument("--timeout", type=int, default=120, help="Wall-clock seconds per NetExec command")
    p.add_argument("--max-log-bytes", type=int, default=8388608, help="Kill a command when captured output exceeds this bound")
    p.add_argument("--cache-max-age-hours", type=float, default=24, help="Maximum completed-check cache age; zero forces recollection")
    p.add_argument("--session-cache-minutes", type=float, default=15, help="Additional maximum age for volatile session checks")
    p.add_argument("--nxc-state", help="Dedicated NetExec state directory; default: OUT/nxc-state")
    p.add_argument("--shared-nxc-state", action="store_true", help="Use inherited NXC_PATH or ~/.nxc instead of isolated state")
    p.add_argument("--doctor", action="store_true", help="Inspect local dependencies and NetExec capabilities, write doctor.json, no target calls")
    p.add_argument("--connect-timeout", type=int, default=3)
    p.add_argument("--skip-port-check", action="store_true", help="Let NetExec attempt SMB/LDAP directly (useful through a proxy)")
    p.add_argument("--nmap", action=argparse.BooleanOptionalAction, default=bool(shutil.which('nmap')), help="Use full-range Nmap discovery when installed (default: automatic); --no-nmap uses configured ports")
    p.add_argument("--nmap-bin", default=shutil.which("nmap") or "nmap", help="Nmap executable for --nmap")
    p.add_argument('--nmap-ports', default='1-65535', help='TCP port ranges for Nmap discovery; default: all TCP ports')
    p.add_argument('--port-map', action='append', default=[], metavar='PROTOCOL:PORT', help='Additional protocol endpoint, repeatable; e.g. ssh:2222')
    p.add_argument('--auto-kerberos', action=argparse.BooleanOptionalAction, default=True, help='Use supplied identity with validated Kerberos when NTLM is unavailable')
    p.add_argument('--ldap-attribute', dest='ldap_attributes', action='append', default=[], metavar='NAME', help='Additional user attribute to read; repeatable')
    p.add_argument('--ldap-schema-dn', help='Override schema naming context when rootDSE discovery is unavailable')
    p.add_argument('--max-ldap-attributes', type=int, default=24, help='Maximum discovered/selected additional attributes')
    p.add_argument("--nxc", default=shutil.which("nxc") or shutil.which("netexec") or "nxc", help="Path to installed NetExec executable")
    p.add_argument("-o", "--out", default="nxc-enum-" + dt.datetime.now().strftime("%Y%m%d-%H%M%S"))
    p.add_argument("--resume", action="store_true", help="Continue an existing output directory; recheck authentication")
    p.add_argument("--refresh", action="store_true", help="Rerun completed checks during --resume")
    p.add_argument("--dry-run", action="store_true", help="Inspect local nxc help and write planned commands without connecting to targets")
    p.add_argument("--list-checks", action="store_true", help="Print the check catalog and exit")
    p.add_argument("--version", action="version", version=VERSION)
    return p


def main():
    os.umask(0o077)
    p = parser()
    args = p.parse_args()
    args.protocols = list(dict.fromkeys(x.strip().lower() for x in args.protocols.split(",") if x.strip()))
    unknown_protocols = sorted(set(args.protocols) - set(PROTOCOL_PORTS))
    if not args.protocols or unknown_protocols:
        p.error("--protocols must contain one or more of: " + ", ".join(PROTOCOL_PORTS) +
                (("; unknown: " + ", ".join(unknown_protocols)) if unknown_protocols else ""))
    for mapping in args.port_map:
        if not re.fullmatch(r'[a-z]+:\d{1,5}', mapping) or mapping.split(':')[0] not in PROTOCOL_PORTS or not 1 <= int(mapping.split(':')[1]) <= 65535:
            p.error('--port-map requires a known protocol and port 1..65535')
        if mapping.startswith('wmi:') and mapping != 'wmi:135':
            p.error('NetExec WMI supports port 135 only')
    if not re.fullmatch(r'\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*', args.nmap_ports):
        p.error('--nmap-ports requires comma-separated TCP ports/ranges')
    for segment in args.nmap_ports.split(','):
        numbers = list(map(int, segment.split('-')))
        if min(numbers) < 1 or max(numbers) > 65535 or numbers[0] > numbers[-1]:
            p.error('Invalid --nmap-ports range')
    if not 1 <= args.max_ldap_attributes <= 128 or any(not re.fullmatch(r'[A-Za-z][A-Za-z0-9-]{0,127}', name) for name in args.ldap_attributes):
        p.error('Invalid LDAP attribute name/count')
    if args.list_checks:
        for c in CHECKS:
            print(f"{c.protocol:4} {c.key:26} {('admin' if c.admin else 'session'):7} {c.title}")
        return 0
    if args.verify_evidence:
        try:
            root = Path(args.out).resolve()
            saved = json.loads((root/'results.json').read_text())
            verification = verify_evidence(root, saved.get('analysis',{}).get('loot',[]))
            atomic_json(root/'integrity-check.json',verification)
            print(json.dumps(collections.Counter(x['status'] for x in verification['files']),indent=2))
            return 0 if verification['passed'] else 3
        except (OSError,ValueError) as exc:
            print('Error: '+str(exc),file=sys.stderr)
            return 2
    if args.analyze_only:
        if not (Path(args.out) / "results.json").is_file():
            p.error("--analyze-only requires an existing --out containing results.json")
        args.resume = True
    if not args.analyze_only and not shutil.which(args.nxc):
        p.error("NetExec executable not found; install nxc or pass --nxc /absolute/path")
    if args.nmap and not args.dry_run and not args.analyze_only and not shutil.which(args.nmap_bin):
        p.error("Nmap executable not found; install nmap or pass --nmap-bin /absolute/path")
    if not args.analyze_only:
        args.nxc = str(Path(shutil.which(args.nxc)).resolve())
    if (args.password_file or args.password_env or args.hash_file) and not args.username:
        p.error("Password/hash input requires --username")
    if args.username and (args.username.startswith("-") or any(c in args.username for c in "\n\r\0")):
        p.error("Invalid username")
    if args.guest_user.startswith("-") or any(c in args.guest_user for c in "\n\r\0"):
        p.error("Invalid guest account name")
    if args.domain and (not valid_target(args.domain) or "/" in args.domain):
        p.error("Invalid domain name")
    if args.dns_server:
        try:
            ipaddress.ip_address(args.dns_server)
        except ValueError:
            p.error("--dns-server must be an IP address")
    if args.kdc_host and not valid_target(args.kdc_host):
        p.error("Invalid --kdc-host")
    if args.nxc_state and args.shared_nxc_state:
        p.error("--nxc-state and --shared-nxc-state cannot be combined")
    if not all(math.isfinite(v) for v in (args.delay, args.cache_max_age_hours, args.session_cache_minutes)):
        p.error("Delay and cache ages must be finite numbers")
    try:
        re.compile(args.content_regex)
    except re.error as exc:
        p.error(f"Invalid --content-regex: {exc}")
    if args.local_auth and args.kerberos:
        p.error("--local-auth and --kerberos cannot be combined")
    if args.credentials_only and not (args.username or args.use_kcache):
        p.error("--credentials-only requires a supplied identity")
    if args.profile == "deep":
        args.bloodhound = args.tickets = args.download_matches = True
        args.module_policy = "loot"
    if args.download_matches:
        args.share_content = True
    if min(args.timeout, args.connect_timeout, args.rid_max, args.max_hosts, args.max_databases, args.max_directories, args.max_matches, args.max_file_bytes, args.path_depth, args.max_paths, args.paths_per_goal, args.max_log_bytes) < 1 or min(args.depth, args.delay, args.cache_max_age_hours, args.session_cache_minutes) < 0:
        p.error("Timeouts, RID maximum and host maximum must be positive; depth must be nonnegative")
    engine = None
    try:
        engine = Engine(args)
        return engine.main()
    except KeyboardInterrupt:
        if engine:
            engine.live.emit("run_interrupted", reason="Stopped by user; retained evidence may be partial")
        print("\nInterrupted. Evidence already collected remains in the output directory.", file=sys.stderr)
        return 130
    except (OSError, ValueError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    finally:
        if engine:
            # An interrupted scan still gets a report for all persisted evidence.
            try:
                if engine.records and not engine.completed:
                    engine.save()
            except (OSError, ValueError, zipfile.BadZipFile) as exc:
                print(f"Could not write final report: {exc}", file=sys.stderr)
            finally:
                engine.temp.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
