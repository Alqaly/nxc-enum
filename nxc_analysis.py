"""Offline evidence triage, loot cataloguing and bounded AD relationship paths.

No network calls or exploitation. Imported relationships are collection-time
observations; a path never asserts that credential or token access succeeded.
"""
from __future__ import annotations

import collections
import csv
import hashlib
import html
import json
from pathlib import Path
import re
import zipfile
from nxc_artifacts import inspect_artifact
import datetime as dt
import sqlite3
from nxc_db import read_database

MAX_IMPORT_BYTES = 64 * 1024 * 1024
MAX_OBJECTS = 100000
MAX_ARTIFACTS = 10000
ACL_RIGHTS = {"GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns",
              "ForceChangePassword", "AddMember", "AddSelf", "ReadGMSAPassword",
              "ReadLAPSPassword", "AllowedToAct", "AllowedToDelegate"}
TRAVERSABLE = ACL_RIGHTS | {"MemberOf", "AdminTo", "HasSession", "CanRDP",
                          "CanPSRemote", "ExecuteDCOM", "TransitiveMemberOf"}
SECRET = re.compile(r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|token|connectionstring|cpassword)\b[\"']?\s*[=:]\s*([^\r\n]+)")
TICKET = re.compile(r"\$(?:krb5asrep|krb5tgs)\$\d+\$")
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
PREFIX = re.compile(r"^[A-Z0-9_.-]+\s+\S+\s+\d+\s+\S+\s+(.*)$")


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def clean(line):
    value = PREFIX.sub(r"\1", ANSI.sub("", line)).strip()
    return re.sub(r"^\[(?:\+|\*|-)\]\s*", "", value)


def private_preview(value):
    """Show the location/key of a candidate without copying its secret value."""
    text = SECRET.sub(lambda m: m[1] + "=<redacted candidate>", value)
    text = re.sub(r'(?i)\b([A-Za-z0-9_-]*(?:password|passwd|pwd|secret|credential|token))[ \t]+[^\r\n]+',
                  r'\1 <redacted candidate>', text)
    text = re.sub(r"(?i)(cpassword\s*=\s*[\"'])[^\"']+", r"\1<redacted candidate>", text)
    return text[:220]


def parse_share(line):
    m = re.match(r"^(.+?)\s+((?:READ|WRITE)(?:[, ]*(?:READ|WRITE))*)(?=\s{2,}|$)", clean(line))
    return (m[1].strip(), m[2].strip()) if m else None


def ldap_objects(text):
    objects, current, previous = [], {}, None
    for line in text.splitlines():
        p = clean(line)
        if "Response for object:" in p:
            if current:
                objects.append(current)
            current = {}
            previous = None
            continue
        m = re.match(r"(sAMAccountName|distinguishedName|objectSid|objectClass|servicePrincipalName|dNSHostName|description|info|member|memberOf|primaryGroupID)\s+(.+)$", p, re.I)
        if m:
            key = m[1].lower()
            if key == "samaccountname" and key in current:
                objects.append(current)
                current = {}
            current.setdefault(key, []).append(m[2].strip())
            previous = key
        elif previous in {"member", "memberof"} and re.match(r"(?i)^(CN|OU|DC)=", p):
            current[previous].append(p)
        elif previous == "objectclass" and re.fullmatch(r"[\w-]+", p):
            current[previous].append(p)
        elif previous == "serviceprincipalname" and re.fullmatch(r"\S+/\S+", p):
            current[previous].append(p)
    if current:
        objects.append(current)
    return objects


class Analysis:
    def __init__(self, out, data, imports=(), starts=(), goals=(), depth=6, max_paths=40, review_file=None, loot_imports=(), paths_per_goal=2):
        self.out, self.data = Path(out).resolve(), data
        self.imports = list(imports)
        self.requested_starts, self.requested_goals = list(starts), list(goals)
        self.depth, self.max_paths = depth, max_paths
        self.paths_per_goal = paths_per_goal
        self.collection_quality = []
        self.artifact_checks = {}
        self.credential_inventory = []
        self.nodes, self.edges, self.findings = {}, {}, {}
        self.starts, self.goals = set(), set()
        self.aliases = {}
        self.warnings = []
        self.import_stats = []
        self.loot, self.secrets = [], []
        self.review = {}
        self.loot_imports = list(loot_imports)
        saved_reviews = self.out / "reviews.json"
        if review_file or saved_reviews.is_file():
            self.review = json.loads(Path(review_file or saved_reviews).read_text(encoding="utf-8"))
            if not isinstance(self.review, dict):
                raise ValueError("Review file must be an object keyed by finding ID")
            if review_file:
                saved_reviews.write_text(json.dumps(self.review, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        self.domain_aliases = {}
        for info in data.get("hosts", {}).values():
            domain = str(info.get("domain", "")).casefold()
            if "." in domain:
                self.domain_aliases[domain.split(".")[0]] = domain

    def safe_file(self, relative):
        path = (self.out / relative).resolve()
        if not path.is_relative_to(self.out):
            raise ValueError("Evidence path points outside output directory")
        return path

    def log(self, record):
        path = self.safe_file(record.get("log", ""))
        return path.read_text(encoding="utf-8", errors="replace") if record.get("log") and path.is_file() else ""

    def canonical(self, label, kind):
        label = str(label).strip().casefold()
        if kind in ("User", "Group"):
            if "@" in label:
                name, domain = label.rsplit("@", 1)
                label = domain + "\\" + name
            if "\\" in label:
                domain, name = label.split("\\", 1)
                label = self.domain_aliases.get(domain, domain) + "\\" + name
        return label

    def node(self, label, kind, object_id=None, highvalue=False):
        key = kind + ":" + self.canonical(label, kind)
        if object_id:
            oid = str(object_id).upper()
            known = self.aliases.get(oid.casefold())
            if known:
                key = known
            elif key in self.nodes and self.nodes[key]["object_ids"] and oid not in self.nodes[key]["object_ids"]:
                self.warnings.append("Conflicting object identifiers for " + str(label) + "; kept as separate nodes")
                key += "#" + oid
        n = self.nodes.setdefault(key, {"id": key, "label": str(label), "kind": kind, "high_value": False, "object_ids": []})
        n["high_value"] |= bool(highvalue)
        self.aliases[str(label).casefold()] = key
        self.aliases[self.canonical(label, kind)] = key
        self.aliases[key.casefold()] = key
        if object_id:
            oid = str(object_id).upper()
            if oid not in n["object_ids"]:
                n["object_ids"].append(oid)
            self.aliases[oid.casefold()] = key
        if highvalue:
            self.goals.add(key)
        return key

    def edge(self, source, target, relation, evidence, confidence="observed", traversable=True):
        eid = digest(source + "|" + relation + "|" + target)
        if eid not in self.edges and len(self.edges) >= 500000:
            raise ValueError("Graph exceeds 500000 relationships")
        edge = self.edges.setdefault(eid, {"id": eid, "source": source, "target": target,
                    "relation": relation, "confidence": confidence, "traversable": traversable, "evidence": []})
        if evidence not in edge["evidence"]:
            edge["evidence"].append(evidence)
        return eid

    def finding(self, category, target, title, priority, evidence, missing, next_step, remediation, confidence="candidate"):
        fid = "F-" + digest(category + "|" + target + "|" + title)
        finding = self.findings.setdefault(fid, {"id": fid, "category": category, "target": target,
                    "title": title, "priority": priority, "confidence": confidence, "status": "needs-review",
                    "evidence": [], "missing_prerequisites": missing, "next_step": next_step, "remediation": remediation})
        if evidence not in finding["evidence"]:
            finding["evidence"].append(evidence)
        review = self.review.get(fid, {})
        if isinstance(review, dict):
            status = review.get("status", "needs-review")
            if status not in {"needs-review", "confirmed", "false-positive", "accepted-risk", "remediated"}:
                raise ValueError("Invalid finding review status: " + str(status))
            finding["status"] = status
            finding["review_note"] = str(review.get("note", ""))[:4000]
        return fid

    def evidence(self, record, line=None):
        item = {"source": record.get("log", ""), "check_id": record["id"], "observed_at": record.get("time"),
                "collection_status": record.get("status")}
        if line:
            item["line"] = line
        return item

    def collect_observations(self):
        records = [r for r in self.data.get("checks", []) if not r.get('historical')]
        for host, info in self.data.get("hosts", {}).items():
            if info.get('historical'):
                continue
            hostname, domain = info.get("hostname", host), info.get("domain", "")
            fqdn = hostname + "." + domain if domain and "." not in hostname else hostname
            node = self.node(fqdn, "Computer")
            self.aliases[host.casefold()] = node
        for user in self.data.get("users", []):
            self.node(user["domain"] + "\\" + user["username"], "User")
        for r in records:
            if r.get("status") not in {"completed", "completed-with-messages", "denied", "timeout"}:
                continue
            text, key, host = self.log(r), r["check"], r["target"]
            info = self.data.get("hosts", {}).get(host, {})
            domain = info.get("domain", "")
            computer = self.aliases.get(host.casefold()) or self.node(host, "Computer")
            ev = self.evidence(r)
            if key == "auth-probe" and r["protocol"] == "smb":
                for line in text.splitlines():
                    if "[+]" not in line:
                        continue
                    m = re.match(r"([^\s:]+)\\([^\s:()]*)?(?::|\s|$)", clean(line))
                    if not m:
                        continue
                    effective = "Guest" if "(Guest)" in line or "Guest: True" in text else m[2] or "ANONYMOUS LOGON"
                    user = self.node(m[1] + "\\" + effective, "User")
                    self.edge(user, computer, "AuthenticatedTo", ev, traversable=False)
                    # Blank anonymous and Guest acceptance never assert a controlled domain user.
                    if r["identity"].startswith("supplied") and effective not in {"Guest", "ANONYMOUS LOGON"}:
                        self.starts.add(user)
                    if "(Pwn3d!)" in line and effective not in {"Guest", "ANONYMOUS LOGON"}:
                        self.edge(user, computer, "AdminTo", ev, confidence="netexec-admin-marker")
                        self.finding("local-admin", host, "Accepted identity has NetExec administrator marker", "P1", ev,
                                     ["Confirm required remote management operation and current token restrictions"],
                                     "Review the local-admin and session evidence for this host.", "Limit local administrator membership and administrative logon exposure.", "observed")
            if key == "banner" and re.search(r"\(signing:False\)", text, re.I):
                self.finding("relay", host, "SMB signing is not required", "P1", ev,
                    ["An authentication source that can reach the relay listener", "A usable NTLM authentication context", "Relayed identity has useful rights on this target", "Other protocol protections and network reachability permit the operation"],
                    "Review signing policy, authentication sources, identity privileges, and exposure on this specific target.", "Require SMB signing and reduce unnecessary NTLM exposure.", "observed")
            if r["protocol"] == "ldap" and re.search(r"\(signing:(?:None|False)\)", text, re.I):
                self.finding("ldap-protection", host, "LDAP signing reported not enforced", "P1", ev,
                    ["Applicable authentication source and target privileges", "Channel binding is a separate LDAPS control"],
                    "Review the LDAP banner and verify the effective domain-controller signing policy.", "Require LDAP signing after validating client compatibility.", "observed")
            if r["protocol"] == "ldap" and re.search(r"\(channel binding:Never\)", text, re.I):
                self.finding("ldap-protection", host, "LDAPS channel binding reported Never", "P1", ev,
                    ["Applicable NTLM/LDAPS authentication context", "Endpoint and identity privileges; TLS alone is insufficient evidence of relay protection"],
                    "Verify the effective channel-binding policy and enrollment/directory endpoint protections.", "Evaluate and enforce appropriate LDAP channel-binding protection.", "observed")
            if key in {"spooler", "webdav"} and re.search(r"\benabled\b", text, re.I):
                self.finding("service-exposure", host, key + " endpoint reported enabled", "P2", ev,
                    ["Coercion-specific prerequisites", "Reachable listener and applicable target protections"],
                    "Correlate this service observation with signing and relay prerequisites; service presence alone is insufficient.", "Disable unnecessary service exposure and enforce authentication protections.", "observed")
            if key == "shares":
                for line in text.splitlines():
                    m = parse_share(line)
                    if not m or m[0].upper() == "IPC$":
                        continue
                    share = self.node(host + "/" + m[0], "Share")
                    principal = self.node(r["identity"] + "@" + host, "CollectionContext")
                    self.edge(principal, share, "ShareAccess:" + m[1], ev, traversable=False)
                    if "WRITE" in m[1]:
                        self.finding("writable-share", host + "/" + m[0], "Share reports write access for " + r["identity"], "P2", ev,
                            ["No file write was performed", "A privileged consumer or executable/script dependency has not been established"],
                            "Check the share's intended writers and any privileged consumers of its files.", "Restrict share and NTFS write permissions.", "observed")
            if key in {"groups", "smb-groups", "rid-users"}:
                for line in text.splitlines():
                    value = clean(line)
                    match = (re.match(r"\d+:\s+(.+?)\s+\(SidTypeGroup\)", value) if key == "rid-users"
                             else re.match(r"(.+?)\s{2,}(\d+)(?:\s+|$)", value))
                    if match:
                        namespace = domain if r["protocol"] == "ldap" else info.get("hostname", host)
                        label = match[1].strip()
                        self.node(label if "\\" in label else namespace + "\\" + label, "Group")
            objs = ldap_objects(text) if r["protocol"] == "ldap" else []
            if key == "recursive-domain-admins":
                group = self.node(domain + "\\Domain Admins", "Group", object_id=info.get("sid", "") + "-512" if info.get("sid") else None, highvalue=True)
                for obj in objs:
                    for name in obj.get("samaccountname", []):
                        classes = {v.casefold() for v in obj.get("objectclass", [])}
                        kind = "Computer" if name.endswith("$") or "computer" in classes else "Group" if "group" in classes else "User"
                        member = self.node(domain + "\\" + name, kind)
                        self.edge(member, group, "TransitiveMemberOf", ev, confidence="transitive-membership-observed")
            if key == "directory-relationships":
                by_dn = {}
                for obj in objs:
                    names, dns = obj.get("samaccountname", []), obj.get("distinguishedname", [])
                    if not names or not dns:
                        continue
                    name = names[0]
                    classes = {v.casefold() for v in obj.get("objectclass", [])}
                    kind = "Computer" if name.endswith("$") or "computer" in classes else "Group" if "group" in classes else "User"
                    high = kind == "Group" and name.casefold() in {"domain admins", "enterprise admins", "administrators", "schema admins"}
                    node = self.node(domain + "\\" + name, kind,
                                     object_id=(obj.get("objectsid") or [None])[0], highvalue=high)
                    by_dn[dns[0].casefold()] = node
                for obj in objs:
                    dns = obj.get("distinguishedname", [])
                    if not dns or dns[0].casefold() not in by_dn:
                        continue
                    principal = by_dn[dns[0].casefold()]
                    sid = (obj.get("objectsid") or [""])[0]
                    primary_rid = (obj.get("primarygroupid") or [""])[0]
                    if re.fullmatch(r"S-1-5-21-(?:\d+-){2}\d+-\d+", sid, re.I) and primary_rid.isdigit():
                        group_sid = sid.rsplit("-", 1)[0] + "-" + primary_rid
                        group = self.aliases.get(group_sid.casefold()) or self.node(group_sid, "Group", object_id=group_sid)
                        self.edge(principal, group, "PrimaryGroupMemberOf", ev, confidence="primary-group-id-observed")
                    for parent_dn in obj.get("memberof", []):
                        parent = by_dn.get(parent_dn.casefold()) or self.node(parent_dn, "Group")
                        self.edge(principal, parent, "MemberOf", ev, confidence="direct-directory-membership")
                    for member_dn in obj.get("member", []):
                        member = by_dn.get(member_dn.casefold()) or self.node(member_dn, "Principal")
                        self.edge(member, principal, "MemberOf", ev, confidence="direct-directory-membership")
            if key in {"no-preauth", "spns", "rbcd", "gmsa-metadata"}:
                for obj in objs:
                    for name in obj.get("samaccountname", []):
                        principal = domain + "\\" + name
                        if key == "no-preauth":
                            self.finding("asrep", principal, "Enabled user listed without Kerberos preauthentication", "P1", ev,
                                ["Recoverability and password strength are unverified"], "Review AS-REP artifact availability and account policy.", "Require Kerberos preauthentication and strong account passwords.", "observed")
                        elif key == "spns" and obj.get("serviceprincipalname"):
                            self.finding("kerberoast", principal, "Account has a service principal name", "P2", ev,
                                ["Ticket collection eligibility and encryption", "Password recoverability is unverified"], "Review account role, encryption settings, rotation, and ticket collection evidence.", "Use managed service accounts where suitable and strong rotated service credentials.", "observed")
                        elif key == "rbcd":
                            self.finding("delegation", principal, "RBCD attribute returned for account", "P1", ev,
                                ["Allowed principals and effective rights must be resolved", "Control of an eligible delegating principal is unverified"], "Resolve the security descriptor and correlate its principals with group/ACL data.", "Remove unintended RBCD principals and protect account ACLs.", "observed")
                        elif key == "gmsa-metadata":
                            self.finding("gmsa", principal, "gMSA identity metadata available", "P3", ev,
                                ["Password-reading permissions are not included in this metadata check"], "Review managed-password read permissions using supported directory ACL collection.", "Limit gMSA password readers and privileged account scope.", "observed")
            if key == "adcs" and "Found CN:" in text:
                self.finding("adcs", host, "AD CS enrollment service discovered", "P2", ev,
                    ["Template ACLs and enrollment eligibility", "EKUs, issuance requirements and certificate mapping", "Enrollment endpoint authentication protections"],
                    "Review CA and template configuration; discovery alone does not establish an ESC vulnerability.", "Restrict enrollment and enforce appropriate issuance and authentication protections.", "observed")
            if key in {"delegation", "unconstrained"}:
                # Ignore banners/authentication headers and summary-only output.
                rows = [clean(l) for l in text.splitlines() if not re.search(r"\(name:|\[\+\]|\[\*\]|\[-\]", l)
                        and re.search(r"unconstrained|constrained|S-1-5-|\b(?:cifs|ldap|http|host)/", l, re.I)]
                if rows:
                    self.finding("delegation", host, "Delegation relationships require review: " + key, "P1", ev,
                        ["Control of the relevant principal", "Allowed services, authentication mode, protected-user restrictions"],
                        "Review the concrete account/service relationship in the attached log and imported graph.", "Remove unintended delegation and keep privileged users off delegated hosts.")
            if key == "logged-on":
                for n, line in enumerate(text.splitlines(), 1):
                    m = re.match(r"([^\s\\]+)\\([^\s]+)\s+logon_server:", clean(line))
                    if m:
                        user = self.node(m[1] + "\\" + m[2], "User")
                        self.edge(computer, user, "HasSession", self.evidence(r, n), confidence="workstation-logon-observation")
            if key == "interactive-sessions":
                for n, line in enumerate(text.splitlines(), 1):
                    m = re.search(r"(?:^|\s)([^\s\\]+)\\([^\s]+)\s+\d+\s+\S+\s+([A-Za-z]+)\b", clean(line))
                    if m:
                        user = self.node(m[1] + "\\" + m[2], "User")
                        evidence = self.evidence(r, n)
                        evidence["session_state"] = m[3]
                        self.edge(computer, user, "HasSession", evidence, confidence="interactive-session-observation")
        for h in self.data.get("review_items", []):
            if h.get('historical'):
                continue
            if "secret" in h.get("title", "").lower():
                ev = {"source": h["source"], "line": h.get("line", 0)}
                self.finding("exposed-secret", h["target"], "Secret-like content in " + h["source"], "P1", ev,
                    ["It may be a placeholder, expired value, or non-secret text", "Associated identity and validity are unverified"],
                    "Review the source file and determine ownership and validity before supplying any credential.", "Remove secrets from readable files and rotate exposed credentials.")

    def inventory(self):
        roots = [self.out / "logs", self.out / "history", self.out / "share-index", self.out / "matched-files", self.out / "bloodhound-imports", self.out / "imported-loot", self.out / "quarantine", self.out / "nxc-state" / "workspaces", self.out / "nxc-state" / "screenshots", self.out / "nxc-state" / "modules"]
        candidates = set()
        for root in roots:
            if root.is_dir() and not root.is_symlink():
                for p in root.rglob("*"):
                    if p.is_file() and not p.is_symlink():
                        candidates.add(p)
                    if len(candidates) > MAX_ARTIFACTS:
                        raise ValueError("Loot inventory exceeds 10000 artifacts; split the output directories")
        for pattern in ("asrep-*.txt", "tgs-*.txt", "users-export-*.txt", "*.zip", "*.ccache", "*.pfx", "*.pem", "*.kdbx"):
            candidates.update(p for p in self.out.glob(pattern) if p.is_file() and not p.is_symlink())
        candidates.update(p for p in (self.out / "users.txt", self.out / "hosts.suggested") if p.is_file())
        associations = {}
        for r in self.data.get("checks", []):
            if r.get("log"):
                associations.setdefault(r["log"], []).append(r["id"])
            for artifact in r.get("artifacts", []):
                associations.setdefault(artifact, []).append(r["id"])
        for h in self.data.get("review_items", []):
            associations.setdefault(h["source"], [])
        total_hashed = 0
        for path in sorted(candidates)[:MAX_ARTIFACTS]:
            path = self.safe_file(path.relative_to(self.out))
            relative = path.relative_to(self.out).as_posix()
            size = path.stat().st_size
            if size > 100 * 1024 * 1024 or total_hashed + size > 512 * 1024 * 1024:
                self.warnings.append("Inventory hash skipped due to byte limits: " + relative)
                sha = None
            else:
                hasher = hashlib.sha256()
                with path.open("rb") as f:
                    for chunk in iter(lambda: f.read(65536), b""):
                        hasher.update(chunk)
                sha = hasher.hexdigest()
                total_hashed += size
            with path.open("rb") as f:
                sample = f.read(262144)
            body = sample.decode("utf-16" if sample.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8", errors="replace")
            kind = "command-log" if relative.startswith("logs/") else "share-index" if relative.startswith("share-index/") else "matched-file" if relative.startswith("matched-files/") else "artifact"
            if path.name.startswith("asrep-"):
                kind = "asrep-material"
            elif path.name.startswith("tgs-"):
                kind = "tgs-material"
            elif path.suffix.lower() in {".zip", ".json"} and "bloodhound" in relative:
                kind = "bloodhound-data"
            elif path.suffix.lower() in {".pfx", ".pem", ".kdbx", ".ccache"}:
                kind = {".pfx": "certificate-container", ".pem": "pem-container", ".kdbx": "password-database", ".ccache": "kerberos-cache"}[path.suffix.lower()]
            elif path.suffix.lower() == ".db":
                kind = "netexec-database"
            item = {"id": "L-" + digest(relative), "path": relative, "kind": kind, "bytes": size, "sha256": sha,
                    "modified_at_epoch": path.stat().st_mtime, "check_ids": associations.get(relative, []),
                    "ticket_markers_in_sample": len(TICKET.findall(body)), "sample_truncated": size > len(sample), "secret_candidates": 0}
            if kind == "matched-file" or relative.startswith("imported-loot/"):
                inspection = inspect_artifact(path)
                item['inspection'] = {key:value for key,value in inspection.items() if key != 'sections'}
                for section in inspection['sections']:
                    for num, line in enumerate(section['text'].splitlines(), 1):
                        if SECRET.search(line) or re.search(r"(?i)cpassword\s*=", line) or "BEGIN PRIVATE KEY" in line or "BEGIN RSA PRIVATE KEY" in line:
                            self.secrets.append({"id": "S-" + digest(relative + ':' + section['source'] + ":" + str(num)), "loot_id": item["id"],
                                "source": relative, 'section':section['source'], "line": num, "preview": private_preview(line), "status": "unverified", "automatically_authenticated": False})
                            item["secret_candidates"] += 1
            item["quarantined"] = relative.startswith("quarantine/")
            self.loot.append(item)

    def retain_loot(self):
        folder = self.out / "imported-loot"
        for filename in self.loot_imports:
            src = Path(filename).resolve()
            if not src.is_file() or src.stat().st_size > MAX_IMPORT_BYTES:
                raise ValueError("Loot import must be an existing file of at most 64 MiB: " + filename)
            body = src.read_bytes()
            folder.mkdir(exist_ok=True, mode=0o700)
            label = re.sub(r"[^A-Za-z0-9_.-]", "_", src.name)[-100:]
            dst = folder / (hashlib.sha256(body).hexdigest()[:16] + "-" + label)
            if not dst.exists():
                dst.write_bytes(body)
            metadata = folder / "provenance.json"
            saved = json.loads(metadata.read_text()) if metadata.exists() else {}
            saved[dst.name] = {"original_name": src.name, "source": "user-supplied evidence"}
            metadata.write_text(json.dumps(saved, ensure_ascii=False, indent=2) + "\n")

    def database_metadata(self):
        # Only state inside this output is discovered automatically. A shared
        # ~/.nxc or externally configured state directory is never swept.
        paths = list((self.out / 'nxc-state' / 'workspaces').glob('*/*.db'))
        paths += list((self.out / 'imported-loot').glob('*.db'))
        for path in sorted(set(paths)):
            path = self.safe_file(path.relative_to(self.out))
            source = path.relative_to(self.out).as_posix()
            try:
                metadata = read_database(path)
            except (ValueError, OSError, sqlite3.DatabaseError) as exc:
                self.warnings.append('Database metadata not imported: ' + source + ' (' + str(exc) + ')')
                continue
            self.warnings.extend(source + ': ' + w for w in metadata['warnings'])
            credentials = {row['id']: row for row in metadata['credentials']}
            hosts = {row['id']: row for row in metadata['hosts']}
            for row in metadata['credentials']:
                self.credential_inventory.append({'source': source, 'database_id': row['id'],
                    'domain': row['domain'], 'username': row['username'], 'kind': row['credtype'],
                    'material_present': row['material_present'], 'status': 'database-record, current validity unverified'})
            for relation in metadata['admin_relations']:
                user, host = credentials.get(relation['userid']), hosts.get(relation['hostid'])
                if not user or not host:
                    continue
                principal = self.node(str(user['domain'] or '')+'\\'+str(user['username'] or ''), 'User')
                name = host['hostname'] or host['ip']
                if not name:
                    continue
                if host['domain'] and '.' not in name:
                    name += '.' + host['domain']
                computer = self.node(name, 'Computer')
                self.edge(principal, computer, 'AdminTo', {'source': source, 'table': 'admin_relations',
                    'database_id': relation['id'], 'observed_at': None, 'time_meaning': 'database contains no observation timestamp'}, 'database-history')

    def copy_imports(self):
        """Retain bounded input artifacts; never extract a ZIP onto the filesystem."""
        folder = self.out / "bloodhound-imports"
        files = list(self.imports)
        for r in self.data.get("checks", []):
            if r["check"] == "bloodhound":
                for match in re.finditer(r"(?:Compressing output into|Saved.*?(?:to|in))\s+([^\r\n]+\.zip)", self.log(r), re.I):
                    p = Path(match[1].strip().strip("'\""))
                    if not p.is_absolute():
                        p = self.out / p
                    if p.is_file():
                        files.append(str(p))
        if folder.exists():
            files.extend(str(p) for p in folder.iterdir() if p.suffix.lower() in {".zip", ".json"} and p.is_file())
        saved = set()
        for file in files:
            src = Path(file).resolve()
            if not src.is_file() or src.suffix.lower() not in {".json", ".zip"}:
                raise ValueError("BloodHound input must be an existing JSON or ZIP file: " + str(file))
            if src.stat().st_size > MAX_IMPORT_BYTES:
                raise ValueError("BloodHound import exceeds 64 MiB: " + str(file))
            blob = src.read_bytes()
            folder.mkdir(exist_ok=True, mode=0o700)
            dst = folder / (hashlib.sha256(blob).hexdigest()[:20] + src.suffix.lower())
            if src != dst.resolve() and not dst.exists():
                dst.write_bytes(blob)
            saved.add(dst)
        return sorted(saved)

    def import_graph(self):
        documents = []
        objects_count, total_bytes = 0, 0
        for path in self.copy_imports():
            label = path.relative_to(self.out).as_posix()
            before = len(documents)
            if path.suffix.lower() == ".zip":
                with zipfile.ZipFile(path) as z:
                    members = [i for i in z.infolist() if i.filename.lower().endswith(".json") and not i.is_dir()]
                    if len(members) > 1000:
                        raise ValueError("BloodHound ZIP has more than 1000 JSON members")
                    for member in members:
                        total_bytes += member.file_size
                        if total_bytes > MAX_IMPORT_BYTES:
                            raise ValueError("BloodHound import exceeds 64 MiB uncompressed across inputs")
                        documents.append((label, member.filename, json.loads(z.read(member))))
            else:
                total_bytes += path.stat().st_size
                if total_bytes > MAX_IMPORT_BYTES:
                    raise ValueError("BloodHound import exceeds 64 MiB across inputs")
                documents.append((label, "", json.loads(path.read_text(encoding="utf-8-sig"))))
            self.import_stats.append({"artifact": label, "documents": len(documents) - before})
            self.artifact_checks[label] = {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                                           "modified_at_epoch": path.stat().st_mtime}
        typed = []
        for source, member, doc in documents:
            if not isinstance(doc, dict) or not isinstance(doc.get("data"), list):
                self.warnings.append("Unsupported BloodHound schema: " + source + "!" + member)
                continue
            meta = doc.get("meta", {})
            if not isinstance(meta, dict):
                self.warnings.append("Invalid BloodHound metadata: " + source + "!" + member)
                continue
            dtype = str(meta.get("type", "")).lower()
            kind = {"users": "User", "groups": "Group", "computers": "Computer", "domains": "Domain", "gpos": "GPO", "ous": "OU"}.get(dtype)
            if not kind:
                self.warnings.append("Unsupported BloodHound object type: " + dtype)
                continue
            for number, obj in enumerate(doc["data"]):
                objects_count += 1
                if objects_count > MAX_OBJECTS:
                    raise ValueError("BloodHound import exceeds 100000 objects")
                if not isinstance(obj, dict) or not obj.get("ObjectIdentifier"):
                    continue
                oid, props = obj["ObjectIdentifier"], obj.get("Properties", {})
                if not isinstance(props, dict):
                    props = {}
                high = bool(props.get("highvalue")) or (kind == "Group" and str(oid).endswith(("-512", "-519")))
                node = self.node(props.get("name") or oid, kind, oid, high)
                typed.append((node, obj, {"source": source, "zip_member": member, "object_index": number,
                                        "object_id": oid, "collector_schema_version": meta.get("version"),
                                        "artifact_sha256": self.artifact_checks[source]["sha256"],
                                        "observed_at": None, "time_meaning": "collector timestamp unavailable; imported file time does not establish session freshness",
                                        "confidence": "imported-collection-observation"}))
        def resolve(oid, kind="Principal"):
            return self.aliases.get(str(oid).casefold()) or self.node(oid, kind, oid)
        ignored = collections.Counter()
        relation_count = 0
        def add(src, dst, relation, ev):
            nonlocal relation_count
            relation_count += 1
            if relation_count > 500000:
                raise ValueError("BloodHound import exceeds 500000 relationships")
            self.edge(src, dst, relation, ev, "imported-observation")
        def results(container, node, method, ev):
            if isinstance(container, dict):
                state = "collected" if container.get("Collected") is True else "failed" if container.get("Collected") is False else "unknown"
                self.collection_quality.append({"node": node, "method": method, "state": state,
                    "failure_reason": container.get("FailureReason"), "source": ev["source"], "object_index": ev["object_index"]})
                if container.get("Collected") is False:
                    return []
                value = container.get("Results", [])
                return value if isinstance(value, list) else []
            if isinstance(container, list):
                self.collection_quality.append({"node": node, "method": method, "state": "legacy-unspecified", "source": ev["source"]})
                return container
            return []
        for node, obj, ev in typed:
            for m in obj.get("Members", []) or []:
                if isinstance(m, dict) and m.get("ObjectIdentifier"):
                    add(resolve(m["ObjectIdentifier"], m.get("ObjectType", "Principal")), node, "MemberOf", ev)
            for name, relation in (("LocalAdmins", "AdminTo"), ("RemoteDesktopUsers", "CanRDP"), ("PSRemoteUsers", "CanPSRemote"), ("DcomUsers", "ExecuteDCOM")):
                container = obj.get(name, {}) or {}
                for m in results(container, node, name, ev):
                    if isinstance(m, dict) and m.get("ObjectIdentifier"):
                        add(resolve(m["ObjectIdentifier"], m.get("ObjectType", "Principal")), node, relation, ev)
            for name in ("Sessions", "PrivilegedSessions", "RegistrySessions"):
                container = obj.get(name, {}) or {}
                for session in results(container, node, name, ev):
                    if isinstance(session, dict) and session.get("UserSID"):
                        # Collector schema: ComputerSID is source, UserSID is destination.
                        add(resolve(session.get("ComputerSID", obj["ObjectIdentifier"]), "Computer"), resolve(session["UserSID"], "User"), "HasSession", ev)
            for local in obj.get("LocalGroups", []) or []:
                if not isinstance(local, dict) or not local.get("ObjectIdentifier"):
                    continue
                lid = str(local["ObjectIdentifier"])
                group = self.node(local.get("Name") or lid, "LocalGroup", lid)
                # Membership itself is informational; selected well-known local RIDs
                # supply a conditional group -> host control/logon relationship.
                members = results(local, node, "LocalGroups:" + lid, ev)
                for member in members:
                    if isinstance(member, dict) and member.get("ObjectIdentifier"):
                        principal = resolve(member["ObjectIdentifier"], member.get("ObjectType", "Principal"))
                        self.edge(principal, group, "MemberOfLocalGroup", ev, "imported-observation", traversable=False)
                        relation = {"544": "AdminTo", "555": "CanRDP", "562": "ExecuteDCOM", "580": "CanPSRemote"}.get(lid.rsplit("-", 1)[-1])
                        if relation:
                            local_ev = dict(ev, local_group_id=lid, composition="selected well-known local group RID")
                            add(principal, node, relation, local_ev)
            for ace in obj.get("Aces", []) or []:
                if not isinstance(ace, dict) or not ace.get("PrincipalSID"):
                    continue
                right = ace.get("RightName", "")
                if right in ACL_RIGHTS:
                    add(resolve(ace["PrincipalSID"], ace.get("PrincipalType", "Principal")), node, right, ev)
                else:
                    ignored[right] += 1
            for name, relation in (("AllowedToDelegate", "AllowedToDelegate"), ("AllowedToAct", "AllowedToAct")):
                for m in obj.get(name, []) or []:
                    if isinstance(m, dict) and m.get("ObjectIdentifier"):
                        other = resolve(m["ObjectIdentifier"], m.get("ObjectType", "Principal"))
                        # AllowedToAct is stored on the target computer: principal -> target.
                        add(other if name == "AllowedToAct" else node, node if name == "AllowedToAct" else other, relation, ev)
        if ignored:
            self.warnings.append("ACL rights omitted from path traversal (no composition engine): " + json.dumps(dict(ignored), sort_keys=True))

    def paths(self):
        starts = set(self.starts)
        if self.requested_starts:
            starts = set()
            for label in self.requested_starts:
                node = self.aliases.get(label.casefold()) or self.aliases.get(self.canonical(label, "User"))
                if node:
                    starts.add(node)
                else:
                    self.warnings.append("Path start not found: " + label)
        goals = set(self.goals)
        if self.requested_goals:
            goals = set()
            for label in self.requested_goals:
                node = self.aliases.get(label.casefold()) or self.aliases.get(self.canonical(label, "Group"))
                if node:
                    goals.add(node)
                else:
                    self.warnings.append("Path goal not found: " + label)
        adjacency = collections.defaultdict(list)
        for edge in sorted(self.edges.values(), key=lambda e: (e["source"], e["relation"], e["target"])):
            if edge["traversable"] and edge["relation"] in TRAVERSABLE:
                adjacency[edge["source"]].append(edge)
        found, expansions = [], 0
        # Enumerate a bounded number of simple paths; a global visited set would
        # hide alternatives and stopping at the first goal would hide later goals.
        for start in sorted(starts):
            queue = collections.deque([(start, [start], [])])
            goal_counts = collections.Counter()
            while queue and len(found) < self.max_paths:
                node, nodes, edges = queue.popleft()
                expansions += 1
                if expansions > 100000:
                    self.warnings.append("Path search reached 100000 node expansions")
                    return found
                if node in goals and goal_counts[node] < self.paths_per_goal:
                    if edges:
                        missing = ["Collection-time relationships and permissions must still be current", "Intermediate principals must be controllable and target operations applicable"]
                        if any(e["relation"] == "HasSession" for e in edges):
                            missing.append("Session type, freshness, usable token/credential availability and host protections are unverified")
                            if any(e["relation"] in {"CanRDP", "CanPSRemote", "ExecuteDCOM"} for e in edges):
                                missing.append("Remote logon permission does not establish local administrator access needed to access another user's session")
                        if any(e["relation"] in ACL_RIGHTS for e in edges):
                            missing.append("Effective ACLs, object type, inheritance, deny ACEs, protection settings and operation-specific requirements must be checked")
                        if any(e["relation"] in {"AllowedToAct", "AllowedToDelegate"} for e in edges):
                            missing.append("Delegating principal control, applicable SPNs/services and protected-user delegation restrictions must be checked")
                        found.append({"id": "P-" + digest(start + "|" + node + "|" + ",".join(e["id"] for e in edges)),
                            "start": start, "goal": node, "nodes": nodes, "edge_ids": [e["id"] for e in edges], "hops": len(edges),
                            "priority": "P1", "status": "candidate", "missing_prerequisites": missing,
                            "next_step": "Review each relationship's attached evidence, current access and missing prerequisites.",
                            "remediation": "Remove unnecessary control/membership edges and prevent privileged session exposure."})
                        goal_counts[node] += 1
                if len(edges) >= self.depth:
                    continue
                for edge in adjacency[node]:
                    if edge["target"] not in nodes:
                        if len(queue) >= 20000:
                            self.warnings.append("Path search reached the 20000-path frontier limit")
                            return found
                        queue.append((edge["target"], nodes + [edge["target"]], edges + [edge]))
        if not starts:
            self.warnings.append("No controlled start principal observed; supply --path-from to examine a specific imported identity")
        return found

    def build(self):
        self.collect_observations()
        self.import_graph()
        self.retain_loot()
        self.database_metadata()
        self.inventory()
        paths = self.paths()
        findings = sorted(self.findings.values(), key=lambda f: (f["priority"], f["category"], f["target"]))
        coverage = collections.defaultdict(collections.Counter)
        for r in self.data.get("checks", []):
            if not r.get('historical'):
                coverage[r["target"]][r["status"]] += 1
        next_steps = [{"kind": "path", "id": p["id"], "priority": p["priority"], "action": p["next_step"]} for p in paths]
        next_steps += [{"kind": "finding", "id": f["id"], "priority": f["priority"], "action": f["next_step"]}
                       for f in findings if f["status"] == "needs-review"]
        for host, counts in coverage.items():
            incomplete = sum(counts[s] for s in ("denied", "timeout", "error", "unsupported", "unreachable", "output-limited", "artifact-oversize", "interrupted"))
            if incomplete:
                next_steps.append({"kind": "coverage", "id": host, "priority": "P2", "action": f"Review {incomplete} incomplete checks for {host}; absence of output cannot establish absence of exposure."})
        result = {"schema_version": 1, "analysis_kind": "evidence-based candidates, no exploit execution", "simulation": bool(self.data.get("simulation")),
                  "nodes": list(self.nodes.values()), "edges": list(self.edges.values()), "paths": paths, "findings": findings,
                  "loot": self.loot, "secret_candidates": self.secrets, "coverage": {h: dict(c) for h, c in coverage.items()},
                  "next_steps": next_steps, "imports": self.import_stats, "warnings": self.warnings,
                  "collection_quality": self.collection_quality,
                  "credential_inventory": self.credential_inventory,
                  "path_limits": {"maximum_hops": self.depth, "maximum_paths": self.max_paths, "paths_per_start_goal": self.paths_per_goal, "node_expansions": 100000, "frontier_limit": 20000}}
        self.write(result)
        return result

    def write(self, result):
        outputs = {"attack-paths.json": {k: result[k] for k in ("schema_version", "nodes", "edges", "paths", "warnings", "path_limits")},
                   "findings.json": result["findings"], "loot.json": result["loot"], "secret-candidates.json": result["secret_candidates"],
                   "next-steps.json": result["next_steps"], "coverage.json": result["coverage"],
                   "collection-quality.json": result["collection_quality"],
                   "credential-inventory.json": result["credential_inventory"],
                   "timeline.json": [{k: r.get(k) for k in ("time", "target", "identity", "check", "status", "seconds", "log")} for r in sorted(self.data.get("checks", []), key=lambda r: r.get("time", ""))]}
        for name, value in outputs.items():
            (self.out / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        for name, rows, fields in (("loot.csv", result["loot"], ["id", "path", "kind", "bytes", "sha256", "secret_candidates", "ticket_markers_in_sample"]),
                                   ("findings.csv", result["findings"], ["id", "priority", "category", "target", "title", "confidence", "status", "next_step", "remediation"])):
            with (self.out / name).open("w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
                writer.writeheader()
                # CSV formula injection prevention for exports opened in spreadsheets.
                writer.writerows({k: "'" + v if isinstance(v, str) and v.lstrip().startswith(("=", "+", "-", "@")) else v for k, v in row.items()} for row in rows)
        (self.out / "evidence.sha256").write_text("\n".join(f"{f['sha256']}  {f['path']}" for f in self.loot if f["sha256"]) + "\n")
        dot = ["digraph CAPE {", "rankdir=LR;"]
        for node in result["nodes"]:
            dot.append(json.dumps(node["id"]) + " [label=" + json.dumps(node["label"]) + "];")
        for edge in result["edges"]:
            dot.append(json.dumps(edge["source"]) + " -> " + json.dumps(edge["target"]) + " [label=" + json.dumps(edge["relation"]) + "];")
        (self.out / "attack-graph.dot").write_text("\n".join(dot + ["}"]) + "\n")
        (self.out / "analysis.html").write_text(render_analysis(result), encoding="utf-8")
        md = ["# Findings for review", "", "Priorities indicate review order, not CVSS severity. Paths are candidates until their prerequisites are verified.", ""]
        for f in result["findings"]:
            md.extend([f"## {f['priority']} · {f['title']}", "", f"ID: {f['id']} · Target: {f['target']} · Status: {f['status']}", "",
                       "Missing: " + "; ".join(f["missing_prerequisites"]), "", "Next: " + f["next_step"], "", "Remediation: " + f["remediation"], ""])
        (self.out / "findings.md").write_text("\n".join(md))


def render_analysis(data):
    esc = lambda value: html.escape(str(value), quote=True)
    nodes = {n["id"]: n for n in data["nodes"]}
    edges = {e["id"]: e for e in data["edges"]}
    def sources(items):
        return " ".join(f"<a href='{esc(i.get('source', ''))}'>{esc(i.get('source', ''))}{':'+esc(i['line']) if i.get('line') else ''}</a>" for i in items if i.get("source"))
    def graph(path):
        # Each path has its own vertical SVG, avoiding an unreadable whole-domain hairball.
        count = len(path["nodes"])
        svg = [f"<svg viewBox='0 0 650 {count * 95}' role='img' aria-label='Candidate relationship path'>"]
        for n, node in enumerate(path["nodes"]):
            svg.append(f"<rect x='10' y='{n*95+5}' width='620' height='44' rx='7' fill='#1f354c'/><text x='22' y='{n*95+33}' fill='#e6edf3' font-size='14'>{esc(nodes[node]['label'][:72])}</text>")
            if n < count-1:
                rel = edges[path["edge_ids"][n]]["relation"]
                svg.append(f"<path d='M 30 {n*95+51} v 38 l -5 -7 m 5 7 l 5 -7' stroke='#65a9eb' fill='none'/><text x='45' y='{n*95+76}' fill='#9ec5e8' font-size='12'>{esc(rel)}</text>")
        return "".join(svg + ["</svg>"])
    css = "body{font:15px system-ui;background:#0b1220;color:#dce6f0;max-width:1280px;margin:30px auto;padding:0 20px}a{color:#86bcf4}nav{display:flex;gap:16px;flex-wrap:wrap}section{margin:30px 0}article,.stats{background:#141f30;border:1px solid #2d3d52;border-radius:10px;padding:18px;margin:12px 0}table{width:100%;border-collapse:collapse}td,th{padding:10px;text-align:left;border-bottom:1px solid #2d3d52;overflow-wrap:anywhere}small{color:#aabacc}input,select,button{padding:10px;background:#1e3045;color:#eef5fc;border:1px solid #506983;border-radius:5px;margin:8px}svg{max-width:660px;width:100%}code{overflow-wrap:anywhere}summary{cursor:pointer}.pill{background:#32445c;border-radius:4px;padding:4px 8px}li{margin:8px 0}pre{white-space:pre-wrap;overflow-wrap:anywhere}"
    page = [f"<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>Attack paths and loot</title><style>{css}</style><h1>Attack paths &amp; loot</h1>"]
    if data.get("simulation"):
        page.append("<p class=stats><b>SIMULATED REPORT — offline fixture, no real network scan</b></p>")
    page.extend(["<nav><a href='report.html'>Command evidence</a><a href='#paths'>Paths</a><a href='#findings'>Findings</a><a href='#loot'>Loot</a><a href='#coverage'>Coverage</a><a href='attack-paths.json'>Graph JSON</a></nav>",
                 f"<p class=stats>{len(data['paths'])} candidate paths · {len(data['findings'])} findings · {len(data['loot'])} evidence artifacts · {len(data['secret_candidates'])} secret candidates</p>",
                 "<p>Priorities are review order. Relationship observations describe collection time; path execution and credential recovery have not been verified.</p>",
                 "<input id=q placeholder='Search paths, findings, loot…' aria-label='Search'><select id=priority aria-label='Priority'><option value=''>All priorities</option><option>P1</option><option>P2</option><option>P3</option></select>",
                 "<section id=paths><h2>Candidate attack paths</h2><p>Bounded alternative relationship paths, ordered by breadth-first search. Default goals are imported high-value objects and observed Domain Admins groups.</p>"])
    for p in data["paths"]:
        ev = [item for eid in p["edge_ids"] for item in edges[eid]["evidence"]]
        page.append(f"<article class=filterable data-priority='{p['priority']}'><h3>{esc(p['id'])} · {p['hops']} hops · candidate</h3>{graph(p)}<b>Missing prerequisites</b><ul>{''.join('<li>'+esc(m)+'</li>' for m in p['missing_prerequisites'])}</ul><p>{esc(p['next_step'])}</p><details><summary>Relationship evidence</summary>{sources(ev)}</details></article>")
    if not data["paths"]:
        page.append("<p>No supported path was found in the available evidence. This does not prove that no attack path exists.</p>")
    page.append("</section><section id=findings><h2>Ranked findings</h2><a href='findings.csv'>CSV</a> · <a href='findings.md'>Report notes</a>")
    for f in data["findings"]:
        page.append(f"<article class=filterable data-priority='{f['priority']}'><span class=pill>{f['priority']}</span><h3>{esc(f['title'])}</h3><p>{esc(f['target'])} · {esc(f['confidence'])} · {esc(f['status'])} · <code>{esc(f['id'])}</code></p><p>Next: {esc(f['next_step'])}</p><details><summary>Prerequisites, evidence and remediation</summary><ul>{''.join('<li>'+esc(m)+'</li>' for m in f['missing_prerequisites'])}</ul><p>{sources(f['evidence'])}</p><p>Remediation: {esc(f['remediation'])}</p><p>{esc(f.get('review_note',''))}</p></details></article>")
    page.append("</section><section id=loot><h2>Loot inventory</h2><p>Raw matched files are retained locally. Secret candidate previews redact values; candidates are not automatically authenticated. Ticket marker counts inspect the first 256 KiB.</p><a href='loot.csv'>CSV</a> · <a href='evidence.sha256'>SHA256 manifest</a><table><thead><tr><th>Artifact</th><th>Type</th><th>Bytes</th><th>Triage</th></tr></thead><tbody>")
    for loot in data["loot"]:
        inspection = loot.get('inspection', {})
        triage = ' · '.join(str(inspection[k]) for k in ('format', 'status') if k in inspection)
        warnings = '; '.join(inspection.get('warnings', []))
        page.append(f"<tr class=filterable><td><a href='{esc(loot['path'])}'>{esc(loot['path'])}</a><details><summary>Hash and provenance</summary><code>{esc(loot['sha256'] or 'Hash skipped: byte limit')}</code><pre>{esc(chr(10).join(loot['check_ids']))}</pre></details></td><td>{esc(loot['kind'])}</td><td>{loot['bytes']}</td><td>{esc(triage)}<br>{esc(warnings)}<br>{loot['secret_candidates']} candidates · {loot['ticket_markers_in_sample']} ticket markers</td></tr>")
    page.append("</tbody></table><h3>Secret candidates</h3>")
    for item in data["secret_candidates"]:
        page.append(f"<article class=filterable><a href='{esc(item['source'])}'>{esc(item['source'])}:{item['line']}</a> {esc(item.get('section', ''))}<pre>{esc(item['preview'])}</pre><small>Unverified · {esc(item['id'])}</small></article>")
    page.append('<h3>NetExec credential metadata</h3><p>Database records are historical. Credential values are omitted; current validity is unverified.</p><a href="credential-inventory.json">Metadata JSON</a><table><thead><tr><th>Identity</th><th>Type</th><th>Source record</th></tr></thead><tbody>')
    for item in data.get('credential_inventory', []):
        identity = str(item['domain'])+'\\'+str(item['username'])
        page.append(f"<tr class=filterable><td>{esc(identity)}</td><td>{esc(item['kind'])}</td><td>{esc(item['source'])} · {esc(item['database_id'])}</td></tr>")
    page.append('</tbody></table>')
    page.append("</section><section id=coverage><h2>Coverage gaps</h2><table><thead><tr><th>Target</th><th>Check statuses</th></tr></thead><tbody>")
    for host, statuses in data["coverage"].items():
        page.append(f"<tr class=filterable><td>{esc(host)}</td><td>{esc(json.dumps(statuses))}</td></tr>")
    page.append("</tbody></table><h3>Next-step queue</h3><ol>" + "".join(f"<li>{esc(x['priority'])} · {esc(x['id'])}: {esc(x['action'])}</li>" for x in data["next_steps"]) + "</ol><h3>Analysis notes</h3><ul>" + "".join("<li>"+esc(w)+"</li>" for w in data["warnings"]) + "</ul></section>")
    quality = collections.Counter(item["state"] for item in data.get("collection_quality", []))
    page.append(f"<section><h2>Collector data quality</h2><p>{esc(dict(quality))}</p><p>Failed collections do not create session/local-admin edges. Unspecified states remain visible as uncertain collection metadata.</p><a href='collection-quality.json'>Full collection metadata</a></section>")
    page.append("<script>const q=document.querySelector('#q'),p=document.querySelector('#priority');function filter(){for(const e of document.querySelectorAll('.filterable'))e.hidden=!(e.textContent.toLowerCase().includes(q.value.toLowerCase())&&(!p.value||!e.dataset.priority||e.dataset.priority===p.value));}q.addEventListener('input',filter);p.addEventListener('change',filter);</script></html>")
    return "".join(page)
