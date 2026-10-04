# NetExec recursive enumeration runner — v0.17.1

## Changes in v0.17.1

- Callback confirmation now requires NetExec's host-context module log shape after a protocol host banner. Output emitted by a module's pre-connection `options()` initialization no longer counts as evidence that `on_login()` or `on_admin_login()` ran.

Give it an IP, hostname, CIDR, target file, or AD domain. It inspects the installed NetExec, probes every selected protocol, tests credential-free access, runs the full catalog of compatible enumeration checks, follows same-domain discoveries, and repeats until the bounded host queue is empty. Start without credentials; add one supplied password, NT hash, or Kerberos cache when available. The default `standard` profile runs broad enumeration; `adaptive` is an explicit faster subset; `deep` adds credential-material collection.

Give it one IP with `python3 nxc_enum.py 10.10.10.10 -o scan`. Start with `scan/summary.md`: it explains which checks and modules ran, what limited coverage, what findings require verification, and what to review next. `scan/report.html` has exact commands and evidence; `scan/analysis.html` has paths, findings and loot. The runner supports SMB, LDAP, MSSQL, RDP, SSH, FTP, NFS, VNC, WinRM, and WMI. On reachable protocols the default profile inventories every installed module and inspects every module's `--options`; it runs reviewed enumeration checks and modules when their prerequisites are met. Input-only, intrusive and unreviewed options remain classified with a reason in `flag-coverage.json` and `module-applicability.json`.

Python 3.10 or newer is required. The wrapper uses the Python standard library for its core flow. NetExec must already be installed and reachable as `nxc` or `netexec`. For domain DNS discovery, install `dnspython` in the Python environment running this wrapper, or have `dig` available. An IP target needs neither.

## Live results

Live terminal output is enabled by default. Target output appears as lines arrive, followed by discoveries such as users, groups, shares and secret candidates. Each check shows its start and final status. Every inventoried module also prints an attempted, unavailable, prerequisite, or policy decision for each host. Same-domain hosts show when they enter the recursive queue. Supported relationships and interpreted findings appear after their originating check completes, with confidence and a next step. A group's reported member count does not establish who those members are.

`events.jsonl` is an append-only structured event stream. `live-map.json` is atomically refreshed after each check with observed nodes and relationships; the final analysis replaces the provisional map. Raw command evidence is written while the command runs. Supplied secrets are redacted; labeled secret candidates are previewed with redacted values in terminal/events, while original candidate evidence remains in protected local logs. Use `--no-live` for quieter terminal output while retaining the event stream. This release supplies the CLI and event interface; it does not include a web server.

## Autonomous enumeration is the default

One IP starts the complete default enumeration flow without interactive input: port detection, name/Kerberos preparation, anonymous/Guest checks, compatible catalog checks, reviewed modules, same-domain host follow-up, SQL database/table follow-up and FTP directory follow-up. Target output and module decisions stream while it runs. The queue stops when eligible work is exhausted or a documented depth, host, directory, output or timeout bound is reached. Limits appear as incomplete coverage, not as proof of a secure target.

FTP follows observed Unix and DOS directory entries, retaining spaces, excluding parent entries and symlinks, and deduplicating jobs. `--depth` and `--max-directories` bound the work. VNC's `No Auth:True` banner establishes credential-free access even without a login success line. Resolved names from LDAP DC discovery feed the host queue; trusted-domain names remain inventory unless they match the selected domain and scope.

New metadata queries enumerate pre-created computer candidates without attempting default passwords, and identify objects with registered key credentials without adding or removing keys. MSSQL encryption, VNC unauthenticated access and NFS root-escape banner values are retained as host observations. These observations do not establish a complete exploitation path.

A supplied username requires a password file/environment variable, hash file or cache. Missing supplied credentials fail with a specific input error rather than prompting. The IP-only run requires no credential input. Target modification, command execution, password guessing and automatic authentication with discovered secret candidates are not part of this enumeration engine.

## Changes in v0.17.0

- Follow-up SMB file reads, FTP directory traversal and SQL table listings use the accepted identity that successfully listed the parent resource. A denied supplied account no longer suppresses follow-up work discovered through Guest, anonymous or another already accepted context.
- Module results distinguish completed callbacks, unconfirmed attempts, failed attempts and partial/limited attempts. `callback_confirmed` records actual module-prefix evidence; starting a process, receiving a diagnostic, or reaching a timeout does not establish a completed callback.
- Resume labels unrechecked prior checks and hosts as historical. Previous administrator markers do not create current `AdminTo` edges or current access findings. Historical rows remain available in the command report, but are excluded from current coverage and module decisions. Reused credential-free cache entries retain their original observation time and a cached label; use `--refresh` to force new probes.
- `--analyze-only` rebuilds reports using saved local capability metadata without accessing NetExec or a target. Offline module applicability no longer fails when no in-memory protocol inspection has run.

## Changes in v0.16.0

- When Nmap is installed, discovery now defaults to TCP ports 1–65535. Known services on supported custom ports feed protocol jobs; every detected endpoint gets separate evidence. Unknown services appear in the summary for external enumeration. Use `--no-nmap` for configured-port socket checks or `--nmap-ports` to narrow discovery. Timeout/error results explicitly mark incomplete coverage. The reviewed NetExec LDAP transport uses fixed ports 389/636, so nonstandard LDAP endpoints are reported as unsupported rather than silently sent to a different port.
- Supplied domain credentials receive one Kerberos fallback on SMB, LDAP, MSSQL, RDP and WMI when NTLM is unavailable and the observed FQDN, realm and KDC prerequisites are available. Invalid, locked or expired accounts do not trigger this fallback. Clock skew, realm, principal, restriction and resolution errors remain distinct diagnostics. Disable with `--no-auto-kerberos`. KDC reachability and credential validity are still established by the authentication attempt.
- Resume rechecks authenticated enumeration, even when the supplied account has not changed, so new permissions, groups and readable resources can be observed. Prior command logs and metadata are retained under `history/<run-id>/`. Current access claims are rebuilt from fresh protocol probes. This favors current evidence over reusing authenticated checks across runs.
- `--download-matches` now feeds bounded share metadata into offline artifact inspection. ZIP, XLSX and DOCX member text/XML, UTF-16 and small standalone base64 text retain section provenance. Encrypted password databases are classified; certificate containers receive metadata inspection when the optional `cryptography` parser can open them without a password. PDF inspection covers basic uncompressed metadata only and reports partial coverage. No archive is extracted or executed. Inspection is bounded to 2 MiB, 64 members and one nested archive level, with expansion limits.
- LDAP attempts schema-context discovery, lists custom attribute definitions, and queries a bounded selection of user attributes. `--ldap-attribute NAME` adds explicit attributes; `--ldap-schema-dn DN` supports installations where RootDSE queries fail; `--max-ldap-attributes` defaults to 24. Attribute values remain unverified evidence.
- Access evidence separates SMB administrator indicators, WinRM access, SQL sysadmin indicators and other protocol authentication. A WinRM or SQL success is no longer labeled as proof of SMB local administrator rights. These meanings appear in `summary.md` and `summary.json`.

## Enumeration coverage

The catalog has 81 checks. Module execution is selected per accepted identity: administrator-only callbacks run only with an identity confirmed as administrator on that target. Module output distinguishes a confirmed callback prefix from a successful NetExec process with no callback evidence. Scope-expanding modules stay manual, deprecated SMB group/computer calls route to LDAP, bounded built-in spidering replaces unbounded metadata spidering, and screenshots/module artifacts enter the evidence inventory.

LDAP automatically selects port 636 when it is the only detected LDAP endpoint. Multi-valued LDAP output preserves additional object classes, members, parent groups and SPNs. Primary group membership uses observed object SID and `primaryGroupID` rather than a guessed group name.

The runner inspects the installed NetExec help and module listings at runtime, then executes only checks supported by that installation.

## Quick start

```bash
# One IP and no credentials: inventory reachable protocols and all installed
# module options, run applicable enumeration, and explain the results.
python3 nxc_enum.py 10.10.10.10 -o scan

# Check local installation and capabilities without contacting targets.
python3 nxc_enum.py --doctor -o installation-check

# A shorter initial checklist.
python3 nxc_enum.py 10.10.10.10 --profile quick -o initial-scan

# Full enumeration plus DCOnly BloodHound, matching-file reads and tickets.
python3 nxc_enum.py 10.10.10.10 -d corp.example -u auditor --password-env NXC_PASSWORD \
  --profile deep -o deep-scan

# One IP, no credentials: install and validate the observed host mapping first,
# then run the full catalog only on detected protocol endpoints.
# null/Guest/anonymous tests, reviewed modules and recursive host discovery.
python3 nxc_enum.py 10.10.10.10 -o scan-one

# Nmap first: parse open ports, service names, hostnames and safe-default NSE
# observations, then dispatch only matching NetExec protocol branches.
# Bounded share-content/secret-candidate and ticket collection are explicit.
python3 nxc_enum.py 10.10.10.10 --nmap --download-matches --tickets -o scan-with-nmap

# Full broad check inventory (also the default profile).
python3 nxc_enum.py 10.10.10.10 --profile standard -o scan-broad

# Audit the options of every installed module without contacting a target.
python3 nxc_enum.py --doctor --inspect-all-module-options -o module-audit

# Also search readable share content, read small matching files,
# and collect AS-REP/TGS material where prerequisites are available.
python3 nxc_enum.py 10.10.10.10 \
  --download-matches --tickets -o scan-full

# Authenticated enumeration uses one password supplied in NXC_PASSWORD.
# There are no interactive prompts; child commands receive no stdin.
python3 nxc_enum.py 10.10.10.10 -d corp.example -u auditor --password-env NXC_PASSWORD \
  --download-matches --tickets -o scan-authenticated

# Continue the first scan with a newly acquired, supplied identity.
# Authentication is rechecked. Earlier completed enumeration is retained.
python3 nxc_enum.py 10.10.10.10 -d corp.example -u auditor --password-env NXC_PASSWORD \
  --resume -o scan-one --download-matches --tickets

# Domain discovery through the AD DNS server, then enumerate discovered
# computer DNS names in that domain (up to --max-hosts).
python3 nxc_enum.py --domain corp.example --dns-server 10.10.10.10 \
  -u auditor --password-env NXC_PASSWORD -o scan-domain

# Hash authentication: the file contains one NT hash or LM:NT pair.
python3 nxc_enum.py 10.10.10.10 -d corp.example -u auditor \
  --hash-file auditor.hash -o scan-hash

# Existing Kerberos cache; use DNS hostnames for Kerberos service naming.
KRB5CCNAME=/path/to/auditor.ccache python3 nxc_enum.py dc01.corp.example \
  -d corp.example --use-kcache -o scan-cache

# Start with a DC IP and a supplied identity. Host mapping is enabled by default;
# use --no-apply-hosts only when system DNS already resolves the observed FQDN.
python3 nxc_enum.py 10.10.10.10 -u auditor --password-env NXC_PASSWORD -k -o scan-kerberos

# Plan without contacting targets. This still reads local NetExec help.
python3 nxc_enum.py 10.10.10.10 --dry-run -o scan-plan

# Run through the Bash launcher if preferred.
bash nxc-enum.sh 10.10.10.10 -o scan-bash
```

For a regular local account, add `--local-auth`; LDAP enumeration will use an anonymous context rather than the local account. Use `--credentials-only` to omit null/Guest attempts. `--guest-user` changes the Guest account name, useful for localized or renamed accounts.

## What the wrapper does

1. Probes the selected protocol ports. With `--nmap`, Nmap version/safe-default NSE results are parsed as structured XML. This discovery step decides which NetExec protocol help and module listings are inspected. A closed RDP port means no RDP help, modules or target commands. `--doctor` deliberately audits all selected local protocol definitions without contacting targets.
2. If SMB is open, the first NetExec target call uses `--generate-hosts-file`. The runner extracts the domain and hostname, installs a marked IP/FQDN mapping and a confirmed DC domain alias in `/etc/hosts` by default, checks for conflicting mappings, and validates the result. `--no-apply-hosts` leaves the mapping in `hosts.suggested`; existing DNS can also satisfy name resolution. An unvalidated IP-to-FQDN mapping withholds supplied Kerberos authentication rather than logging a false credential failure.
3. When NetExec detects a DC, the runner invokes `--generate-krb5-file` separately because upstream selects one generator per call. It checks the generated realm and KDC name, records the file hash, and uses the validated file as `KRB5_CONFIG` unless the operator set one, and routes later Kerberos commands through the FQDN with a KDC address when supported.
4. Tests the supplied identity and null authentication per protocol. SMB also tests Guest, FTP tests anonymous access, and NFS export discovery runs without a credential exchange. A failure on one protocol does not block the same identity on another.
5. Runs compatible built-in checks and reviewed modules. The order of preference is supplied credentials, null, then Guest/anonymous. A check denied in one accepted context can fall back to another. Visible MSSQL databases feed bounded per-database table enumeration.
6. Builds a deduplicated account inventory from RID results, exports, and LDAP queries. RID results separate users from groups and machine accounts; SMB/SAMR identities keep the host name as their account namespace because they may be local accounts.
7. Collects directory metadata: users, groups, OUs, computers, policies, delegation, trusts, SPNs, no-preauthentication users, gMSA identities, AD CS, sites/subnets, SCCM, Entra synchronization servers, script paths, GPOs, and OU links.
8. Resolves Domain Admins by its domain SID plus RID 512, then performs a transitive membership query. Reads the domain-root DACL when the base DN is available.
9. Follows AD CS enrollment service names into their published template lists.
10. In the standard and adaptive profiles, runs the LDAP `get-network` module in host-name mode when available, retains a bounded copy of its DNS-name artifact, and adds same-domain names to the queue. A confirmed DC address is reused as a DNS server unless one is supplied. Repeats against these and directory-discovered computers until no new in-scope host remains or `--max-hosts` is reached.
11. Produces reports with commands, observations, status, and logs. The report opens locally in a browser; no server is needed.

`module-applicability.json` records a decision for every installed module on each scanned host: attempted, blocked by endpoint/authentication/admin prerequisites, excluded by profile/policy, removed, or manual review. Each decision points to check evidence where available. `results.json` includes a status count. A completed command does not prove that its target condition exists.

The catalog contains the original **50 SMB/LDAP checks** plus protocol-specific FTP, NFS, MSSQL, RDP, SSH, WinRM, and WMI checks. Extra checks are generated for directory relationships, reviewed modules, certificate templates, shares, matching files, and optional ticket collection. `--list-checks` prints the actual catalog.

## Attack paths, loot and review

| Feature | What you get |
|---|---|
| Candidate paths | Bounded alternative paths from an accepted supplied SMB identity or a selected principal to observed high-value objects. Each hop has evidence; session paths include missing token/credential prerequisites. |
| BloodHound import | Collector-format JSON or ZIP: groups, local administrators, sessions, selected ACL rights, delegation and high-value identities. Imports are retained locally without extracting ZIP members. |
| Visual paths | A vertical SVG for each path in `analysis.html`, plus graph JSON and Graphviz DOT. |
| Ranked findings | P1/P2/P3 review priorities for signing exposure, secret candidates, AS-REP account settings, SPNs, delegation, AD CS discovery, writable shares, and administrator observations. These priorities are not CVSS scores. |
| Loot inventory | File type, size, SHA256, originating check, ticket markers, and bounded secret-candidate counts. Includes files downloaded by the wrapper and supplied evidence imports. |
| Secret triage | Redacted candidate previews with file and line references; raw files remain local. Candidates stay unverified until reviewed. UTF-16 files with a BOM are supported. |
| Review state | Stable finding IDs with needs-review, confirmed, false-positive, accepted-risk and remediated states, plus notes. Saved states survive report rebuilds. |
| Scan comparison | New, retained, and no-longer-observed finding/path IDs compared with an earlier `results.json`. |
| Coverage and timeline | Per-host status counts, incomplete-check queue and timestamped command activity. |
| Offline rebuild | Re-analyze saved evidence and imports without NetExec installed or any network request. |
| Exports | Findings Markdown/CSV/JSON, loot CSV/JSON, secret candidates JSON, next-step queue, graph and evidence manifest. |

### Collect and inspect

```bash
# Directory graph collection alongside enumeration and matching share files.
python3 nxc_enum.py dc01.corp.example -d corp.example -u auditor --password-env NXC_PASSWORD \
  --bloodhound --download-matches --tickets -o scan

# Include host session/local-admin collection where permissions allow it.
python3 nxc_enum.py dc01.corp.example -d corp.example -u auditor --password-env NXC_PASSWORD \
  --bloodhound --bloodhound-collection All -o scan-with-sessions

# Existing BloodHound collector data; no target connections.
python3 nxc_enum.py --analyze-only -o scan \
  --import-bloodhound collection.zip --path-from 'CORP\\auditor'

# A specific goal, supplied by name or SID.
python3 nxc_enum.py --analyze-only -o scan \
  --path-from 'CORP\\auditor' --path-to 'CORP\\Domain Admins' \
  --path-depth 8 --max-paths 40

# Add an existing evidence file to the loot inventory.
python3 nxc_enum.py --analyze-only -o scan --import-loot service.config

# Compare separate scan directories. Scope and coverage still matter.
python3 nxc_enum.py --analyze-only -o scan-new \
  --compare scan-old/results.json
```

`DCOnly` gathers directory relationships; it does not collect workstation sessions. `All` performs extra host enumeration and can take much longer. The wrapper retains and imports the ZIP path printed by NetExec when that file exists; use `--import-bloodhound` if your installation stores it elsewhere. Multiple imports are deduplicated by content hash.

The importer supports collector `data`/`meta` JSON with `ObjectIdentifier` records, legacy local-admin fields, and current SharpHound `LocalGroups` results. `Collected: false` suppresses session/local-group edges and records the failure as a coverage gap. Selected local group RIDs generate conditional AdminTo/remote-logon relations while original membership is retained as non-traversable provenance. It does not import arbitrary BloodHound API responses, AzureHound/OpenGraph schemas, or perform BloodHound's full edge-composition logic. Unsupported types and ACL rights are reported. Raw `GetChanges` rights are **not** automatically treated as DCSync. Import limits: 64 MiB uncompressed across graph inputs, 100000 objects and 500000 relationships. Path limits: two alternatives per start/goal, six hops and forty paths by default; at most 100000 node expansions and a 20000-path frontier. Use `--paths-per-goal` to change the alternative count. This is a partial evidence graph, not an exhaustive attack-path verdict. Imported file timestamps are not treated as session observation timestamps.

SMB signing, service presence, SPNs, and AD CS discovery produce findings with explicit missing prerequisites. They do not become invented principal-control edges. A `HasSession` relationship does not establish that a usable token or credential is available. The wrapper does not execute candidate paths.

### Record your review

Copy a finding ID from the report into a JSON file:

```json
{
  "F-copy-the-id-from-your-report": {
    "status": "false-positive",
    "note": "The source contained a documented placeholder."
  }
}
```

Apply it with `python3 nxc_enum.py --analyze-only -o scan --review-file review.json`. The wrapper saves it as `scan/reviews.json`. A manually confirmed finding does not automatically turn a candidate path into verified execution.

Loot inventory hashes up to 100 MiB per file and 512 MiB per rebuild, with a 10000-artifact limit. Files above a hash limit are listed with a warning. Ticket triage samples the first 256 KiB. Matched/imported artifact inspection is separately limited to 2 MiB of source and expanded content; oversize, encrypted, partial and unsupported formats are labeled. Kerberos caches are categorized without ticket decoding. Ticket marker counts are format observations, not proof of successful password recovery.

## Profiles, state, scope and freshness

`standard` is the one-IP default: it runs every cataloged enumeration check for reachable protocols and accepted contexts, inspects the options of installed modules for those protocols, and invokes reviewed discovery modules. Closed protocol ports are marked unreachable without loading that protocol's help or modules. Unavailable flags, missing access, active/state-changing modules, and modules whose behavior has not been reviewed remain explicitly reported. `adaptive` opts into a faster selection and labels omitted checks as skipped. `quick` selects 14 base checks plus banner/authentication and applicable follow-up queries. `deep` adds matching-file reads, tickets, credential-reading modules and DCOnly BloodHound. Host-wide BloodHound collection is selected separately with `--bloodhound-collection All`.

NetExec receives a dedicated `NXC_PATH=OUT/nxc-state` in its child environment. Your shell environment and HOME are unchanged. Use `--nxc-state /path/to/client-state` to retain state elsewhere, or `--shared-nxc-state` to use your inherited `NXC_PATH`/`~/.nxc` configuration. Fresh isolated state uses NetExec's default configuration. Isolated databases can contain credential values written by NetExec; raw state files remain sensitive evidence. Report metadata never selects password/hash values from those databases.

The analysis reads compatible NetExec `users`, `hosts` and `admin_relations` tables in read-only mode. Database identities and credential types appear in `credential-inventory.json`; historical administrator relations can enrich the graph but never establish a currently controlled start identity. Shared state outside the output directory is not swept. To review an existing database explicitly, use `--import-loot smb.db` during an offline rebuild.

```bash
# Follow same-domain directory discoveries until the host cap is reached.
python3 nxc_enum.py 10.10.10.10 -d corp.example -u auditor --password-env NXC_PASSWORD \
  --follow-discovery --allow 10.10.10.0/24 \
  --exclude 10.10.10.66 --delay 1 --max-hosts 64 -o scoped-scan

# Select names directly; rules can be repeated and support hostname globs.
python3 nxc_enum.py dc01.corp.example --allow '*.corp.example' \
  --exclude restricted.corp.example -o named-scan

# Use fresh observations with TCP DNS and an explicit KDC where supported.
python3 nxc_enum.py dc01.corp.example -d corp.example -u auditor --password-env NXC_PASSWORD -k \
  --dns-server 10.10.10.10 --dns-tcp --kdc-host dc01.corp.example \
  --resume --refresh -o scoped-scan

# Verify saved evidence without rebuilding/replacing its hash baseline.
python3 nxc_enum.py --verify-evidence -o scoped-scan
```

Scope rules cover wrapper-managed target selection. Exclusions take precedence; when checking CIDR rules against a hostname, excluded resolved addresses reject the target. A CIDR-only allow list requires every resolved address to match. Dry runs perform no target DNS resolution. NetExec/BloodHound and their libraries can make indirect DNS/DC/host connections; these wrapper rules are not a network isolation mechanism. See NetExec's [host exclusion boundary](https://www.netexec.wiki/getting-started/configuration/config-hostexclusion).

Resume cache entries require matching normalized command options and NetExec version. Completed entries expire after 24 hours; session checks have an additional 15-minute age limit. Change these with `--cache-max-age-hours` and `--session-cache-minutes`; zero disables reuse. Authentication probes are always rerun. Changed permissions or credentials for the same account still warrant `--refresh`.

`--delay` sets the minimum interval between wrapper target invocations; it does not control internal NetExec/module retries. `--max-log-bytes` defaults to 8 MiB: a noisy command is terminated and marked `output-limited`. Transfers are polled for size growth and oversized matching files are moved to `quarantine/`, excluded from text triage. Polling and buffering can overshoot the configured file bound. Output killed at a limit is partial evidence. `--verify-evidence` writes `integrity-check.json` and exits 0 when every baseline entry matches, 3 for changed/missing/unverified entries, and 2 for an input error. It never replaces `results.json` or the manifest.

### Optional steps

| Switch | Behavior |
|---|---|
| `--share-content` | Searches readable share files for the configured regex, to a default depth of 3. |
| `--download-matches` | Enables content search and reads matching files with reported size at most 256 KiB, up to 20 reads per identity/host share-search pass. Extracts secret-like lines for review. |
| `--tickets` | Uses discovered usernames for unauthenticated AS-REP collection when LDAP login is unavailable; accepted LDAP contexts can collect AS-REP material, and supplied domain credentials can collect Kerberoast material. |
| `--follow-discovery` / `--no-follow-discovery` | Recursive same-domain host enumeration is enabled by default and bounded by `--max-hosts`; the negative switch disables it. |
| `--nmap / --no-nmap` | Structured port/service/NSE discovery, enabled when Nmap is installed. Defaults to all TCP ports; timeout means incomplete coverage. XML is saved under `nmap/`. |
| `--nmap-ports PORTS` | Override the default `1-65535` TCP discovery range. |
| `--port-map PROTOCOL:PORT` | Add a known service endpoint, repeatable. WMI remains fixed to 135; reviewed LDAP transport remains 389/636. |
| `--auto-kerberos / --no-auto-kerberos` | Default supplied-domain-identity fallback for unavailable NTLM, gated by validated names and KDC context. |
| `--ldap-attribute NAME` | Add an explicit user attribute to bounded schema-driven directory queries; repeatable. |
| `--ldap-schema-dn DN` | Supply the schema search base if automatic discovery cannot retrieve it. |
| `--max-ldap-attributes N` | Bound custom/selected attribute coverage, default 24. |
| `--protocols smb,ldap,...` | Selects protocols; the default is all ten supported protocols. |
| `--module-policy inventory` | Records installed modules and their options without running automatic modules. |
| `--module-policy safe` | Default: runs reviewed read-only discovery modules that need no extra operator input. |
| `--module-policy loot` | Adds reviewed credential-reading modules. `--profile deep` selects this policy automatically. |
| `--bloodhound` | Adds a `DCOnly` collection artifact; report generation does not require opening BloodHound. |
| `--bloodhound-collection All` | Includes extra host enumeration when collecting BloodHound data. |
| `--analyze-only` | Rebuilds reports, graph and loot from an existing output directory without network calls. |
| `--doctor` | Writes local installation/capability metadata; no target calls. |
| `--verify-evidence` | Checks saved hashes without replacing their baseline. |
| `--control-checks` | Runs the legacy LDAP signing checker if the installed version still exposes it and does not mark it removed. Recent NetExec versions report signing/channel-binding information in their core LDAP banner. |
| `--no-spider` | Omits recursive share-file metadata collection. |
| `--ldaps` | Uses LDAP port 636. |
| `--skip-port-check` | Lets NetExec attempt connections directly, useful through a proxy. |
| `--resume --refresh` | Resume rechecks authenticated observations and preserves replaced logs under `history/`; refresh also bypasses other reusable checks. |

`--content-regex`, `--depth`, `--max-matches`, `--max-file-bytes`, `--rid-max`, `--max-hosts`, `--max-databases`, `--timeout`, and `--connect-timeout` control the work performed. Hosts and commands are processed sequentially; NetExec's thread count is set to one for each invocation. A large domain can take substantial time.

## Output

| File | Purpose |
|---|---|
| `report.html` | Local searchable checklist, status filters, review items, embedded evidence, full-log links. |
| `report.md` | Markdown checklist with evidence links. |
| `results.json` | Versioned results schema for a future web frontend. |
| `analysis.html` | Candidate paths, ranked findings, loot and coverage dashboard. |
| `attack-paths.json`, `attack-graph.dot` | Evidence graph and bounded path candidates. |
| `findings.json`, `findings.csv`, `findings.md` | Ranked findings, review states, prerequisites and remediation notes. |
| `loot.json`, `loot.csv`, `evidence.sha256` | Artifact inventory and content-integrity manifest. |
| `secret-candidates.json` | Redacted, unverified candidate references. |
| `next-steps.json`, `coverage.json`, `timeline.json` | Triage queue, coverage gaps and command timeline. |
| `action-trace.json` | Source observation → queued host/protocol branch for the feedback loop. |
| `nmap/*.xml`, `network-names/*.txt` | Structured Nmap evidence and bounded same-domain NetExec DNS names used to feed recursion. |
| `delta.json` | Finding/path changes when `--compare` was supplied. |
| `reviews.json` | Saved manual review states and notes. |
| `collection-quality.json` | Collected, failed, unknown and legacy collection states. |
| `credential-inventory.json` | NetExec database identity/type metadata with credential values omitted. |
| `doctor.json`, `integrity-check.json` | Local diagnostic or evidence verification results when requested. |
| `scanned-targets.txt`, `scope_decisions` in JSON | Actual wrapper-managed targets and rule decisions. |
| `nxc-state/`, `quarantine/` | Dedicated NetExec state and oversized matching-file evidence. |
| `bloodhound-imports/`, `imported-loot/` | Retained supplied evidence with content-hash filenames. |
| `users.txt` | Combined username inventory. This is not automatically treated as a credential list. |
| `ticket-users-*.txt` | Domain-filtered username list used for optional unauthenticated AS-REP requests. |
| `users-export-*.txt` | Original NetExec user exports per host, protocol, and identity. |
| `discovered-hosts.txt` | Computer DNS names discovered through directory queries. |
| `targets.txt` | Initial targets. Additional scanned targets appear in `results.json`. |
| `hosts.suggested`, `hosts/*.txt` | NetExec-generated host mappings and their deduplicated combined view; installation and validation are enabled by default. |
| `krb5.generated.conf` | NetExec-generated realm file for a detected DC; used as `KRB5_CONFIG` for Kerberos calls unless already set by the operator. It contains no ticket or credential. |
| `capabilities.json` | Flags and module descriptions discovered from the installed NetExec. |
| `flag-coverage.json` | Every discovered CLI flag, classified as a cataloged check, conditional/input setting, or manual review. This makes unsupported automation visible. |
| `module-inventory.json`, `module-options/` | Every installed module across selected protocols, its automatic/manual classification, and locally captured option documentation. |
| `module-applicability.json` | Per-host status and reason for every installed module, with check evidence IDs. |
| `UPSTREAM_CAPABILITY_AUDIT.json` | Static source audit of 10 protocols, 222 CLI option definitions, and 136 upstream modules at the pinned commit. |
| `logs/` | Captured output for every executed command. |
| `share-index/` | Recursive share metadata from `spider_plus`. |
| `matched-files/` | Raw matching files if `--download-matches` was selected. |
| `asrep-*.txt`, `tgs-*.txt` | Optional ticket material. |

Output directories/files use restrictive creation permissions on Unix. Supplied passwords/hashes are redacted from commands, logs, and reports. They are provided to NetExec through a temporary private file, deleted when the wrapper exits. NetExec manages its database/artifacts in the selected state directory and may store credentials there. Downloaded files and raw databases remain evidence and may contain secrets.

## Reading the status correctly

| Status | Meaning |
|---|---|
| `completed` | The command completed. It is not a vulnerability verdict or a clean bill of health. |
| `completed-with-messages` | The command returned zero but emitted diagnostic failure markers; inspect its evidence. |
| `denied` | An operation was denied. Some output may still be useful. |
| `auth-failed` | Authentication failed. Subsequent supplied-identity attempts stop. |
| `unsupported` | A flag/module is unavailable or a module is marked removed. |
| `skipped` | A prerequisite or selected option is absent. |
| `timeout` | The process was killed at its wall-clock limit. Output may be partial. |
| `unreachable` | The wrapper could not connect to the selected TCP port. |
| `error` | A subprocess/runtime/parser error occurred. |
| `planned` | Dry-run command only. No target connection was made. |
| `excluded` | A wrapper target-selection rule excluded this host. |
| `output-limited` | The subprocess output bound was reached; command killed, evidence partial. |
| `artifact-oversize` | Actual downloaded file size exceeded the bound; evidence quarantined. |
| `interrupted` | User stopped the active command; partial captured output retained. |

## Practical limitations

- Automatic enumeration covers all ten NetExec protocols when their endpoints are observed. Every installed module is inventoried, but modules that mutate accounts/ACLs, coerce authentication, execute payloads, require missing operator parameters, or have not been reviewed remain `manual-only-unreviewed-or-active`. The runner never assumes that “installed” means safe to execute.
- Exposed-secret candidates are not automatically used for authentication. Supply a verified account/password or hash and resume. Automatically guessing which account belongs to a string in a file would make the results unreliable.
- The wrapper interprets human-readable NetExec output. It retains the original evidence if formatting changes. User exports and explicit LDAP attribute queries provide more reliable inventory than text-table parsing.
- A Guest-mapped named login is not proof that the named account's password was valid. It can enumerate what Guest can access. `Pwn3d!` is used as NetExec's admin-access observation, not a Domain Admin verdict.
- `adminCount=1` is historical metadata, and `PASSWD_NOTREQD` does not prove a blank password. A service endpoint, configured delegation, or an SPN alone does not prove exploitability. AD CS discovery/template names are not a complete ESC audit.
- The domain-root DACL check is not an exhaustive effective-rights analysis across every object. Group memberships, deny ACEs, inheritance, and privileges still matter. `--bloodhound` supplies extra directory collection if needed.
- Share content searches return matched paths and offsets, not necessarily the matching plaintext. `--download-matches` reads eligible files for excerpts. Reported-size eligibility and live file-growth checks are both used; buffering can still overshoot the limit. Binary documents and UTF-16 without a BOM are not fully decoded by the excerpt scanner.
- SMB signing observations and LDAP signing observations are stored separately. An unsigned SMB endpoint is one prerequisite, not a guaranteed relay-to-execution path.
- Each check starts a separate NetExec process and can authenticate again. The adaptive profile removes many redundant checks but is not yet a single NetExec process or a measured performance guarantee. Successful credentials may subsequently expire or be revoked; authentication failure stops further attempts with that identity only for the same host and protocol. Library/module-internal retries are controlled by NetExec itself.
- Resume keys include host, protocol, identity and check. Cache entries validate request options/version and evidence age. Older entries without a fingerprint are recollected. Use `--refresh` after permissions or configuration change, or use a new directory for another engagement. The wrapper does not recover killed commands' internal state.
- The process-group timeout and interrupt cleanup are implemented for Unix. On Windows only the direct subprocess is terminated. Kali/Linux is the intended first runtime.

## Verification

Run the offline integration tests:

```bash
python3 -m unittest discover -s tests -v
```

The fixture simulates current upstream CLI flags, successful/failed identities, Guest-only access, directory output, removed modules, matched file reads, timeouts, and old-version flags. It makes no network connections. A live AD lab was not available in the build environment; real LDAP permissions, DNS/Kerberos behavior, module-specific output, and large-domain performance still need validation on your environment.

The demo report in `demo-output/` is explicitly **simulated output**. It shows the report layout and schema, not a real scan.

The regression suite covers current local-group schema, failed collections, alternative paths, goals beyond the first high-value node, Kerberos cache output, database metadata, resource caps, scope rules, resume/access changes, profiles, relative BloodHound ZIP output, oversized-download quarantine, bounded DNS recursion, multiple service endpoints, Kerberos fallback/diagnostics, custom attributes and bounded archive/document inspection. `verification.json` records the executed suite and prior validation history. A live AD/Nmap integration run remains outstanding.

## Source basis

Wiki review completed on 2026-10-02; source reviewed against upstream commit `3e0e37e8b563602d94938adf92725da269f8dafe`. Runtime help determines what actually runs on your machine.

- [NetExec official repository](https://github.com/Pennyw0rth/NetExec)
- [SMB argument definitions](https://github.com/Pennyw0rth/NetExec/blob/3e0e37e8b563602d94938adf92725da269f8dafe/nxc/protocols/smb/proto_args.py)
- [LDAP argument definitions](https://github.com/Pennyw0rth/NetExec/blob/3e0e37e8b563602d94938adf92725da269f8dafe/nxc/protocols/ldap/proto_args.py)
- [NetExec protocol loader](https://github.com/Pennyw0rth/NetExec/blob/3e0e37e8b563602d94938adf92725da269f8dafe/nxc/loaders/protocolloader.py)
- [NetExec module loader](https://github.com/Pennyw0rth/NetExec/blob/3e0e37e8b563602d94938adf92725da269f8dafe/nxc/loaders/moduleloader.py)
- [Null sessions](https://www.netexec.wiki/smb-protocol/enumeration/enumerate-null-sessions)
- [Share spidering](https://www.netexec.wiki/smb-protocol/spidering-shares)
- [Delegation](https://www.netexec.wiki/ldap-protocol/find-misconfigured-delegation)
- [User exports](https://www.netexec.wiki/ldap-protocol/enumerate-users)
- [BloodHound HasSession semantics](https://bloodhound.specterops.io/resources/edges/has-session)
- [BloodHound MemberOf direction](https://bloodhound.specterops.io/resources/edges/member-of)
- [BloodHound AdminTo semantics](https://bloodhound.specterops.io/resources/edges/admin-to)

The wrapper is independent orchestration code, not a modified NetExec distribution. The test capability snapshot contains factual CLI flags and selected upstream module descriptions with attribution to NetExec.

The complete source-to-change matrix and remaining work are in [RESEARCH.md](RESEARCH.md).
