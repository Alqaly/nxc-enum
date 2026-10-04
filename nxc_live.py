"""Live terminal output, JSONL events and an evolving evidence map."""
from __future__ import annotations
import codecs
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import threading
import uuid

from nxc_analysis import clean, parse_share, private_preview


class EventStream:
    def __init__(self, out: Path, display=True):
        self.out, self.display = out, display
        self.path = out / "events.jsonl"
        self.run_id, self.sequence = uuid.uuid4().hex, 0
        self.lock = threading.Lock()
        self.observed = set()
        self.nodes, self.edges = {}, {}

    def emit(self, kind, **fields):
        with self.lock:
            self.sequence += 1
            event = {"schema_version": 1, "run_id": self.run_id, "sequence": self.sequence,
                     "time": datetime.now(timezone.utc).isoformat(), "type": kind, **fields}
            with self.path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(event, ensure_ascii=False) + "\n")
            if self.display:
                if kind == "output":
                    print(f"  {fields['text']}", flush=True)
                elif kind in {"user", "group", "computer", "share", "secret_candidate", "relationship", "finding"}:
                    label = fields.get("title", fields.get("name", ""))
                    if kind == "relationship":
                        label = f"{fields['source']} {fields['relation']} {fields['destination']} [{fields['confidence']}]"
                    print(f"[{kind.upper():18}] {fields.get('target', '')} {label}", flush=True)
                    if kind == "finding":
                        print(f"  Next: {fields['next_step']}", flush=True)
                elif kind in {"host_started", "host_queued", "check_started", "protocol_ready"}:
                    print(f"[{kind:18}] {fields.get('target', '')} {fields.get('protocol', '')} {fields.get('title', '')}", flush=True)
                elif kind == "module_options":
                    state = "timeout" if fields['timed_out'] else f"exit {fields['returncode']}"
                    print(f"[module_options    ] {fields['protocol']} {fields['name']} ({state})", flush=True)
                elif kind == "module_decision":
                    print(f"[module_result     ] {fields['target']} {fields['protocol']} {fields['name']}: {fields['status']} — {fields['reason']}", flush=True)
                elif kind == "directory_queued":
                    print(f"[directory_queued  ] {fields['target']} {fields['protocol']} {fields['path']}", flush=True)
                elif kind == 'access_capability':
                    print(f"[access            ] {fields['target']} {fields['protocol']}:{fields['port']} {fields['effective_identity']}: {fields['capability']} ({fields['method']})", flush=True)
                elif kind == 'auth_method_fallback':
                    print(f"[auth_fallback     ] {fields['target']} {fields['protocol']}: {fields['method']} — {fields['reason']}", flush=True)
                elif kind == 'artifact_inspected':
                    print(f"[artifact          ] {fields['path']}: {fields['format']} · {fields['status']}", flush=True)
            return event

    def observation(self, kind, **fields):
        key = json.dumps([kind, fields.get("target"), fields.get("protocol"), fields.get("name"),
                          fields.get("attribute"), fields.get("value"), fields.get("status"),
                          fields.get("confidence")], sort_keys=True)
        if key not in self.observed:
            self.observed.add(key)
            self.emit(kind, **fields)

    def update_map(self, analysis, final=False, replace=False):
        if final or replace:
            self.emit("map_reset", reason="Replace provisional relationships with the latest aggregate analysis")
            self.nodes, self.edges = {}, {}
        for node in analysis.get("nodes", []):
            if node["id"] not in self.nodes:
                self.emit("map_node", node=node)
            self.nodes[node["id"]] = node
        for edge in analysis.get("edges", []):
            if edge["id"] not in self.edges:
                self.emit("relationship", relation=edge["relation"], source=edge["source"],
                          destination=edge["target"], evidence=edge["evidence"], confidence=edge["confidence"],
                          traversable=edge.get("traversable", False))
            self.edges[edge["id"]] = edge
        for finding in analysis.get("findings", []):
            self.observation("finding", name=finding["id"], title=finding["title"], target=finding["target"],
                             confidence=finding["confidence"], next_step=finding["next_step"],
                             evidence=finding["evidence"], status=finding["status"],
                             missing_prerequisites=finding["missing_prerequisites"])
        snapshot = {"schema_version": 1, "final": final, "run_id": self.run_id,
                    "nodes": list(self.nodes.values()), "edges": list(self.edges.values()),
                    "meaning": "Observed relationships; object rights, session freshness and exploitability still require verification"}
        temporary = self.out / "live-map.tmp"
        temporary.write_text(json.dumps(snapshot, ensure_ascii=False), encoding="utf-8")
        temporary.replace(self.out / "live-map.json")
        self.emit("map_snapshot", path="live-map.json", nodes=len(self.nodes), edges=len(self.edges), final=final)


class LiveOutput:
    def __init__(self, stream, target, protocol, check, source, redact, log_path=None):
        self.stream = stream
        self.fields = {"target": target, "protocol": protocol, "check": check, "source": source}
        self.decoder = codecs.getincrementaldecoder("utf-8")("replace")
        self.pending, self.line = "", 0
        self.redact = redact
        self.finished = False
        self.log_path = log_path
        if log_path:
            log_path.write_text("", encoding="utf-8")

    def __call__(self, chunk):
        self.pending += self.decoder.decode(chunk)
        while "\n" in self.pending:
            line, self.pending = self.pending.split("\n", 1)
            self.handle(line)

    def finish(self):
        if self.finished:
            return
        self.finished = True
        self.pending += self.decoder.decode(b"", final=True)
        if self.pending:
            self.handle(self.pending)
        self.pending = ""

    def handle(self, line):
        self.line += 1
        if self.log_path:
            with self.log_path.open("a", encoding="utf-8") as log:
                log.write(self.redact(line) + "\n")
        line = self.redact(clean(line))
        if not line:
            return
        preview = private_preview(line) if re.search(r"(?i)password|passwd|pwd|secret|credential|cpassword", line) else line[:4000]
        fields = {**self.fields, "line": self.line}
        self.stream.emit("output", **fields, text=preview)
        key = self.fields["check"]
        if key == "rid-users":
            match = re.match(r"\d+:\s+(.+?)\s+\(SidType(User|Group)\)", line)
            if match:
                kind = "group" if match[2] == "Group" else "computer" if match[1].endswith("$") else "user"
                self.stream.observation(kind, **fields, name=match[1])
        if key in {"ldap-users", "smb-users", "active-users"}:
            match = re.match(r"(\S+)\s+(?:\d{4}-\d{2}-\d{2}|<never>|0\s)", line)
            if match:
                self.stream.observation("user", **fields, name=match[1])
        if key in {"groups", "smb-groups"}:
            match = re.match(r"(.+?)\s{2,}(\d+)(?:\s+|$)", line)
            if match:
                self.stream.observation("group", **fields, name=match[1].strip(), members_reported=int(match[2]))
        if key == "shares" and (share := parse_share(line)):
            self.stream.observation("share", **fields, name=share[0], permissions=share[1])
        match = re.match(r"(sAMAccountName|dNSHostName|memberOf|member)\s+(.+)$", line, re.I)
        if match:
            attribute, value = match[1].lower(), match[2].strip()
            if attribute == "dnshostname":
                self.stream.observation("computer", **fields, name=value)
            elif attribute == "samaccountname":
                # Object class arrives separately; do not assume every account is a user.
                self.stream.observation("account", **fields, name=value)
            else:
                self.stream.observation("directory_attribute", **fields, attribute=attribute, value=value)
        if re.search(r"(?i)\b(password|passwd|pwd|secret|cpassword)\s*[:=]", line):
            self.stream.observation("secret_candidate", **fields, name="Review candidate in retained evidence", value=private_preview(line))
