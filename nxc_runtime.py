"""Bounded subprocess capture and explicit wrapper target selection."""
from __future__ import annotations
import fnmatch
import ipaddress
import os
import signal
import subprocess
import threading
import time
import hashlib
from pathlib import Path


class CaptureInterrupted(KeyboardInterrupt):
    def __init__(self, output):
        self.output = output


def terminate(proc):
    if os.name == "nt":
        if proc.poll() is None:
            proc.kill()
    else:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def capture(command, cwd, env, timeout, maximum, monitored_file=None, maximum_file=None, on_chunk=None):
    """Drain a single pipe with a bounded reader; kill on timeout/output limit."""
    started = time.monotonic()
    proc = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            cwd=cwd, env=env, start_new_session=os.name != "nt")
    data = bytearray()
    reader_errors = []
    done, limited = threading.Event(), threading.Event()
    def read():
        try:
            while True:
                chunk = os.read(proc.stdout.fileno(), 65536)
                if not chunk:
                    break
                remaining = maximum - len(data)
                data.extend(chunk[:remaining])
                if on_chunk and remaining:
                    on_chunk(chunk[:remaining])
                if len(chunk) > remaining:
                    limited.set()
                    break
        except Exception as exc:
            reader_errors.append(exc)
            terminate(proc)
        finally:
            done.set()
    thread = threading.Thread(target=read, daemon=True)
    thread.start()
    expired, interrupted, file_limited = False, False, False
    try:
        while not done.wait(0.05):
            if limited.is_set():
                break
            if monitored_file and monitored_file.is_file() and monitored_file.stat().st_size > maximum_file:
                file_limited = True
                break
            if time.monotonic() - started >= timeout:
                expired = True
                break
        if limited.is_set() or expired or file_limited:
            terminate(proc)
        remaining = max(0.05, timeout - (time.monotonic() - started))
        try:
            proc.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            expired = True
            terminate(proc)
            proc.wait(timeout=5)
    except KeyboardInterrupt:
        interrupted = True
        terminate(proc)
        proc.wait(timeout=5)
    finally:
        thread.join(timeout=1)
        if thread.is_alive():
            terminate(proc)
            thread.join(timeout=1)
        if not thread.is_alive():
            proc.stdout.close()
    output = bytes(data).decode("utf-8", errors="replace")
    if reader_errors:
        raise RuntimeError("Subprocess output reader failed") from reader_errors[0]
    if interrupted:
        raise CaptureInterrupted(output)
    return output, proc.returncode, expired, "artifact-size" if file_limited else "output" if limited.is_set() else "", round(time.monotonic()-started, 2)


class Scope:
    def __init__(self, allow=(), exclude=()):
        self.allow, self.exclude = list(allow), list(exclude)
        self._rules = {}
        for rule in self.allow + self.exclude:
            if not rule or rule.startswith("-") or any(c.isspace() for c in rule):
                raise ValueError("Invalid scope rule: " + repr(rule))
            try:
                self._rules[rule] = ipaddress.ip_network(rule, strict=False)
            except ValueError:
                if "/" in rule:
                    raise ValueError("Invalid scope CIDR: " + rule)
                self._rules[rule] = rule.casefold().rstrip(".")

    def matches(self, value, rules):
        for rule in rules:
            matcher = self._rules[rule]
            if isinstance(matcher, str):
                if fnmatch.fnmatchcase(value.casefold().rstrip("."), matcher):
                    return True
            else:
                try:
                    if ipaddress.ip_address(value) in matcher:
                        return True
                except ValueError:
                    pass
        return False

    def decision(self, host, addresses=()):
        if self.matches(host, self.exclude) or any(self.matches(a, self.exclude) for a in addresses):
            return False, "excluded target/name/address"
        if not self.allow or self.matches(host, self.allow):
            return True, "explicit target or matching name rule"
        if addresses and all(self.matches(a, self.allow) for a in addresses):
            return True, "all resolved addresses match allow rules"
        return False, "target is outside supplied allow rules or unresolved"


def verify_evidence(directory, inventory):
    """Compare saved inventory hashes without rebuilding the baseline."""
    root = Path(directory).resolve()
    checks = []
    for item in inventory:
        path = (root / item['path']).resolve()
        if not path.is_relative_to(root):
            raise ValueError('Evidence path points outside output directory')
        state, actual = 'unverified', None
        if not path.is_file():
            state = 'missing'
        elif item.get('sha256'):
            # Original inventory caps hashing at 100 MiB per file. Changed files
            # exceeding that bound are size-changed without reading unbounded data.
            if path.stat().st_size != item['bytes']:
                state = 'size-changed'
            elif path.stat().st_size <= 100*1024*1024:
                hasher = hashlib.sha256()
                with path.open('rb') as f:
                    for block in iter(lambda:f.read(65536),b''):
                        hasher.update(block)
                actual = hasher.hexdigest()
                state = 'matched' if actual == item['sha256'] else 'hash-changed'
        checks.append({'path':item['path'],'status':state,'expected_sha256':item.get('sha256'),'actual_sha256':actual})
    return {'baseline':'saved results.json analysis.loot; not replaced', 'files':checks,
            'passed':bool(checks) and all(x['status']=='matched' for x in checks)}
