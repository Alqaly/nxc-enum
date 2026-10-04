# Research and improvement record — v0.6.0

Reviewed on 2026-10-01. This record connects source material and observed code defects to implemented changes. It also distinguishes completed work from remaining validation. No live Active Directory environment was scanned during this build.

## Verified source basis

The NetExec repository HEAD was checked remotely and matched the local reviewed commit:

`3e0e37e8b563602d94938adf92725da269f8dafe`

SharpHoundCommon source was retrieved from its official repository and reviewed at:

`04220411f1e68f8f05874158f538783a3f5a6bb7`

| Source | What it established | Result in the wrapper |
|---|---|---|
| [NetExec database usage](https://www.netexec.wiki/getting-started/database-general-usage) and [paths.py](https://github.com/Pennyw0rth/NetExec/blob/3e0e37e8b563602d94938adf92725da269f8dafe/nxc/paths.py) | NetExec persists credentials and uses NXC_PATH for state. | Dedicated child NXC_PATH per output, explicit shared-state opt-in, masked database metadata. |
| [NetExec SMB database schema](https://github.com/Pennyw0rth/NetExec/blob/3e0e37e8b563602d94938adf92725da269f8dafe/nxc/protocols/smb/database.py) | Users, hosts and administrator relations provide structured evidence. | Read-only SQLite importer with known-column checks, bounded row counts and a query time budget; no credential value selection. |
| [NetExec host exclusion](https://www.netexec.wiki/getting-started/configuration/config-hostexclusion) | Direct exclusions do not prevent all indirect connections. | Allow/exclude rules for wrapper-managed targets, resolved-address checks, and an explicit boundary in the guide. |
| [NetExec credentials](https://www.netexec.wiki/getting-started/using-credentials) and [Kerberos](https://www.netexec.wiki/getting-started/using-kerberos.md) | Authentication output differs for cache use; throttling can be local to a host. | Cache-authentication graph parsing and a minimum interval between wrapper invocations. |
| [NetExec LDAP implementation](https://github.com/Pennyw0rth/NetExec/blob/3e0e37e8b563602d94938adf92725da269f8dafe/nxc/protocols/ldap.py) | Signing and channel-binding observations are independent fields. | Separate stored control fields and evidence-backed LDAP protection findings. |
| [Microsoft LDAP signing guidance](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) | Security defaults depend on version and deployment history; TLS and channel binding differ. | Findings use observed controls rather than assume protection from OS version or LDAPS alone. |
| [SharpHound Computer output](https://github.com/SpecterOps/SharpHoundCommon/blob/04220411f1e68f8f05874158f538783a3f5a6bb7/src/CommonLib/OutputTypes/Computer.cs), [LocalGroupAPIResult](https://github.com/SpecterOps/SharpHoundCommon/blob/04220411f1e68f8f05874158f538783a3f5a6bb7/src/CommonLib/OutputTypes/APIResults/LocalGroupAPIResult.cs), [APIResult](https://github.com/SpecterOps/SharpHoundCommon/blob/04220411f1e68f8f05874158f538783a3f5a6bb7/src/CommonLib/OutputTypes/APIResult.cs) | Current local-group output differs from older direct LocalAdmins fields; results include collection state. | Both formats are supported. Failed collections create coverage metadata, not usable graph edges. |
| [BloodHound data quality](https://bloodhound.specterops.io/collect-data/data-quality) and [collection permissions](https://bloodhound.specterops.io/collect-data/sharphound-data-permissions) | Local-group and session completeness depend on collection success and permissions. | Collection quality is displayed separately from command status. |
| [AdminTo](https://bloodhound.specterops.io/resources/edges/admin-to), [HasSession](https://bloodhound.specterops.io/resources/edges/has-session), [MemberOfLocalGroup](https://bloodhound.specterops.io/resources/edges/member-of-local-group) | Session presence does not establish usable credential access; local membership and control relationships differ. | Paths retain missing prerequisites, local membership provenance, and conditional selected-group compositions. |
| [Python subprocess documentation](https://docs.python.org/3.15/library/subprocess.html#subprocess.Popen.communicate) | communicate buffers output in memory; timeout cleanup must terminate the child. | Bounded pipe capture, process-group termination on Unix, partial output on timeout/interrupt and explicit output-limit status. Uses APIs available in Python 3.10+. |
| [NetExec file retrieval](https://www.netexec.wiki/smb-protocol/get-and-put-files) and direct code audit | A generic file retrieval operation does not make a previously reported size an immutable guarantee. | Live size polling and post-transfer checks quarantine oversized matches and exclude them from text triage. |
| [NetExec CLI definitions](https://github.com/Pennyw0rth/NetExec/blob/3e0e37e8b563602d94938adf92725da269f8dafe/nxc/cli.py) | DNS TCP and KDC routing are runtime capabilities. | DNS TCP and KDC options are passed when the installed CLI exposes them; local DNS supports TCP. |

The source-to-implementation choices are engineering judgments. The sources do not certify this wrapper or validate its execution against a live domain.

## Improvement passes

1. **Execution and evidence reliability:** dedicated NetExec state, smaller/expanded profiles, bounded stdout capture, wrapper pacing, request/version fingerprints, cache expiry, volatile-session expiry, explicit scope rules and a discovery queue bounded by host count.
2. **Graph and loot correctness:** modern local-group imports, failed collection-state handling, bounded alternative simple paths, goals beyond the first high-value node, Kerberos cache output, source hashes/object indexes, LDAP control separation and read-only credential metadata.
3. **Follow-up defect fixes:** relative generated BloodHound archive paths, file growth monitoring, quarantine behavior, share names with spaces, finite numeric option validation, safer spreadsheet exports and an integrity check that preserves its original baseline.

The graph search previously used a global visited set and stopped expanding after reaching a goal. That discarded alternatives and could hide a high-value object reachable through another goal. The updated search uses cycle checks per path and explicit frontier, depth, expansion and output bounds. This is still a partial, conditional graph; it does not reproduce BloodHound's complete composition engine.

4. **Protocol-wide recursive enumeration:** inspected all 10 protocol argument definitions (222 CLI options) and 136 module classes at the pinned NetExec commit; added runtime help/module listing, per-protocol authentication state, FTP anonymous and NFS credential-free discovery, protocol-specific enumeration, default same-domain recursion, and reviewed automatic module policies. The machine-readable source snapshot is `UPSTREAM_CAPABILITY_AUDIT.json`. Standard/deep now read every installed module's options per protocol; adaptive/quick read selected ones unless `--inspect-all-module-options` is supplied.
5. **Adaptive action pass:** the optional adaptive profile prioritizes checks that feed the host/identity graph, omits lower-priority duplicate calls with explicit `skipped` records, and invokes LDAP `get-network` in host-name mode. Its bounded NetExec-generated artifact is copied into the scan and same-domain names are queued. Broad `standard` is now the default. This changes call selection, but no live-domain speedup has yet been measured.
6. **Nmap feedback pass:** optional `--nmap` runs TCP connect/version detection with `default and safe and not broadcast and not external` NSE scripts on selected NetExec service ports, retains bounded XML, parses matching-host open ports, services, script observations and hostnames, then dispatches only the applicable protocol branches and queues discovered same-domain names. The parser does not treat arbitrary script text as credentials or a vulnerability verdict. Official [NSE usage](https://nmap.org/book/nse-usage.html) documents the categories and warns that scripts are not sandboxed; [XML output](https://nmap.org/book/output-formats-xml-output.html) is intended for programmatic processing. Live-network behavior is unverified here.
7. **Module applicability pass:** the installed module inventory now receives a per-target decision in `module-applicability.json`, linked to executed check IDs. Endpoint, accepted authentication, administrator grouping from `nxc <protocol> -L`, selected profile, and credential-reading policy are separate reasons. Unknown and active modules remain manual review; an attempted module is not represented as a positive finding. NetExec's [module documentation](https://www.netexec.wiki/getting-started/using-modules) confirms `-L` and `-M ... --options`; its [module loader](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/netexec.py) separates low and high privilege listings.
8. **Full-enumeration and Kerberos bootstrap pass:** made standard broad enumeration the default, added missing SMB computer/session/directory/snapshot/WMI checks, MSSQL login context and bounded table follow-up, and WMI snapshot checks, plus reviewed WMI/SSH/WinRM module entries. Standard/deep inspect every installed module's option documentation on detected protocol endpoints; `flag-coverage.json` shows every inspected runtime flag and the automation decision. NetExec's [SMB generator implementation](https://github.com/Pennyw0rth/NetExec/blob/3e0e37e8b563602d94938adf92725da269f8dafe/nxc/protocols/smb.py) uses `if` / `elif` for host and Kerberos file generation, so the wrapper calls them separately. It retains per-host mappings, assembles `hosts.suggested`, installs and validates conflict-checked FQDN/short-name entries and a confirmed DC domain alias in the system hosts file by default, validates the generated realm/KDC and hashes its contents before applying it when a caller has not provided `KRB5_CONFIG`, and routes Kerberos target names via FQDN plus the detected DC address as KDC where supported. This is offline fixture verified; live AD DNS, clock, realm and ticket behavior is not yet validated.
9. **Bootstrap order and protocol gating:** the first SMB target command generates the hosts file. The runner validates the installed FQDN mapping before a supplied Kerberos authentication attempt. Protocol help, module listings, and options are read only for endpoints discovered open on at least one scanned host; a local `--doctor` explicitly inspects all selected protocols without target traffic. The no-SMB and failed-hosts-write paths have offline regression cases.

### Writeup-to-runner comparison (illustrative, not a machine-solvability count)

| Author's lab sequence | Automatable part in this runner | Boundary |
|---|---|---|
| [0xdf Retro](https://0xdf.gitlab.io/2025/06/24/htb-retro.html): SMB domain banner, unauthenticated share failure, Guest share access, RID cycling, readable file. | Banner, null/Guest branching, share listing, RID users, optional bounded share-content review. | The later account password guess and certificate abuse are not automatic. |
| [0xdf Delegate](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html): Guest/Null signals, RID list, open SMB share with a script, followed by BloodHound/targeted abuse. | RID and share inventory, optional bounded content/loot collection, optional BloodHound data collection. | Deciding that a leaked credential is valid and changing directory state require separate review. |
| [0xdf Scepter](https://0xdf.gitlab.io/2025/07/19/htb-scepter.html): supplied identity enumerates LDAP users and collects BloodHound, revealing a password-change edge. | Given one supplied identity, LDAP user/group/ACL inventory and optional BloodHound collection. | `change-password` is a state-changing module and is not auto-run. |
| [0xdf Resolute](https://0xdf.gitlab.io/2020/05/30/htb-resolute.html): user-description secret hint, then a broad password spray and manual lateral steps. | Extract users/descriptions and report a secret candidate with source evidence. | The spray and unverified credential reuse are deliberately excluded. |

These are four selected first-person writeups, not a representative sample of all Hack The Box or VulnLab machines. "Solved by NetExec" has no stable public denominator and often includes external tools, guesses, or state-changing steps. The runner claims enumeration coverage, not autonomous domain compromise.

10. **Readable scan output:** one-IP standard runs now emit `summary.md` and `summary.json`. The summary groups results by host/protocol, counts attempted and inventoried modules, states the most common reason for uncovered modules, and presents evidence-linked finding prerequisites and next steps. The installed protocol and module `--help`/`--options` inventory remains version-specific; input-only, active and unreviewed actions are documented but not executed automatically.

11. **Live evidence pass:** subprocess pipes now use immediate byte reads with a bounded callback. Target lines, users/groups/shares and candidate previews stream to the terminal and append-only JSONL events. Per-check evidence is written while the child runs; supported graph relationships/findings are interpreted when the check completes. An atomic live-map snapshot distinguishes provisional checks from queue completion. A handshake regression test proves that callbacks occur before the child exits; split UTF-8, split-secret redaction, timeouts, resource limits, resume and final-event ordering are verified with offline fixtures.

## Validation evidence

`verification.json` contains the executed test count and reviewed commits. The offline fixture never connects to a network.

Regression scenarios include failed session data that still contains stale Results; current local-group RIDs; two alternatives to one goal; another goal after the first; cache output without a password separator; SQLite metadata with a secret that must not appear in the report; unchanged database bytes after analysis; changed command depth; cache expiry; oversized file growth; bounded process output; same-size evidence modification; exclusion precedence; relative collection archives; and HTML escaping.

The simulated report includes an intentionally inconsistent object identifier from separately generated fixture data. It demonstrates the conflict warning and separate-node behavior; it is not evidence of a real domain contradiction.

## Remaining work, ranked

| Priority | Work | Completion evidence required |
|---|---|---|
| P1 | Live AD acceptance tests | Anonymous/Guest, password, NT hash and cache runs; signing-enforced LDAP/LDAPS; delegated collector permissions; observed findings compared with known lab ground truth. |
| P1 | Effective-rights and composition engine | Cross-check deny ACEs, inheritance, owner rules, SID history and DCSync prerequisites against BloodHound results; preserve object-type semantics. Raw rights alone are insufficient. |
| P1 | Collector compatibility fixtures | Real redacted exports from supported BloodHound CE Python and SharpHound versions, including mixed schema versions, session failures and AD CS object types. |
| P2 | AD CS configuration import | A supported structured CA/template input and validated eligibility/mapping rules before assigning ESC classifications. Discovery is not an ESC audit. |
| P2 | Large-domain performance | Measure adaptive versus standard wall-clock time, process count and host coverage on a permitted lab; profile 10k/100k-object imports, output size, graph search, evidence hashing and resume. |
| P2 | Packaging and cross-version CI | Install/run checks on Python 3.10–3.13 and more than one NetExec release, plus Unix interrupt and descendant cleanup validation. |
| P2 | Browser/report QA | Desktop/mobile rendering, filtering and evidence-link tests with an actual browser. The build environment did not contain a runnable Chromium binary. |
| P3 | Protected evidence bundles | Deliberate key/password management, encryption and recoverability tests; raw loot and NetExec state can contain secrets. |
| P3 | Web frontend | An authenticated local interface over the existing results schema, with server-side target selection and job cancellation. No web server is included in this release. |

These items remain open. They are not silently counted as implemented or verified features.

## v0.12.0 coverage corrections

Reviewed the official documentation index at https://www.netexec.wiki/llms.txt and relevant enumeration pages against pinned NetExec source. Added nine catalog entries, with explicit WDigest check, tombstone query and MSSQL enum_priv modes. Source callback metadata fills absent administrator requirement headings in runtime module listings. Runtime listings remain the primary inventory. Every inventoried module emits a per-host applicability decision.

LDAP now probes both 389 and 636 by default, selecting 636 for a 636-only endpoint. The parser preserves unlabelled continuation values from NetExec's LDAP query formatter and maps observed primaryGroupID membership. Twenty-six targeted offline tests passed in 16.174 seconds; real domain behavior is unverified.

## v0.13.0 runtime improvements

Implemented bounded FTP directory follow-up, VNC No Auth banner acceptance, and parsing of resolved DC names into the same-domain queue. Added metadata-only pre-created-computer and key-credential-presence queries. Removed interactive password input and closed subprocess stdin. Existing credentials must be supplied explicitly; newly discovered secret candidates are retained for review and are not automatically authenticated.
