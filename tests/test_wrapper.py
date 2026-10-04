"""Integration tests for adaptation, evidence, identity handling and subprocess limits."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "nxc_enum.py"
FAKE = ROOT / "tests/fake_nxc.py"
FAKE_NMAP = ROOT / "tests/fake_nmap.py"


class FlowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.out = self.base / "run"
        self.calls = self.base / "calls.jsonl"
        (self.base / "hosts").write_text("127.0.0.1 localhost\n")

    def tearDown(self):
        self.tmp.cleanup()

    def run_wrapper(self, *extra, env_extra=None):
        env = os.environ.copy()
        env.update({"NXC_FAKE_CALLS": str(self.calls)})
        env.update(env_extra or {})
        port_control = [] if "--nmap" in extra else ["--skip-port-check"]
        result = subprocess.run([sys.executable, str(SCRIPT), "192.0.2.10", "--nxc", str(FAKE),
                                 *port_control, "--out", str(self.out), "--system-hosts-file",
                                 str(self.base / "hosts"), *extra],
                                capture_output=True, text=True, env=env, timeout=90)
        return result

    def data(self):
        return json.loads((self.out / "results.json").read_text())

    def test_share_followup_uses_the_context_that_listed_shares(self):
        password = self.base / 'pass.txt'
        password.write_text('EXAMPLE-SECRET\n')
        result = self.run_wrapper('--protocols', 'smb', '--no-follow-discovery', '--download-matches',
                                  '-u', 'auditor', '--password-file', str(password),
                                  env_extra={'NXC_FAKE_ENUM_FALLBACK':'1'})
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        reads = [c for c in calls if '--get-file' in c]
        self.assertTrue(reads)
        self.assertTrue(all(c[c.index('-u')+1] == 'Guest' for c in reads))

    def test_ftp_followup_uses_anonymous_listing_context(self):
        password = self.base / 'pass.txt'
        password.write_text('EXAMPLE-SECRET\n')
        result = self.run_wrapper('--protocols', 'ftp', '--no-follow-discovery', '-u', 'auditor',
                                  '--password-file', str(password),
                                  env_extra={'NXC_FAKE_ENUM_FALLBACK':'1', 'NXC_FAKE_FTP_TREE':'1'})
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        children = [c for c in calls if '--ls' in c and c[c.index('--ls')+1] != '.']
        self.assertTrue(children)
        self.assertTrue(all(c[c.index('-u')+1] == 'anonymous' for c in children))

    def test_sql_followup_uses_successful_database_context(self):
        password = self.base / 'pass.txt'
        password.write_text('EXAMPLE-SECRET\n')
        result = self.run_wrapper('--protocols', 'mssql', '--no-follow-discovery', '-u', 'auditor',
                                  '--password-file', str(password),
                                  env_extra={'NXC_FAKE_ENUM_FALLBACK':'1', 'NXC_FAKE_DATABASES':'1'})
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        children = [c for c in calls if '--database' in c and c.index('--database')+1 < len(c)]
        self.assertTrue(children)
        self.assertTrue(all(c[c.index('-u')+1] == '' for c in children))

    def test_failed_module_does_not_claim_a_confirmed_callback(self):
        result = self.run_wrapper('--protocols', 'smb', '--no-follow-discovery',
                                  env_extra={'NXC_FAKE_FAIL_MODULE':'spooler'})
        self.assertEqual(result.returncode, 0, result.stderr)
        decisions = json.loads((self.out/'module-applicability.json').read_text())
        spooler = next(d for d in decisions if d['module'] == 'spooler')
        self.assertEqual(spooler['status'], 'attempted-failed')
        self.assertFalse(spooler['callback_confirmed'])

    def test_module_warning_without_prefix_is_unconfirmed(self):
        result = self.run_wrapper('--protocols', 'smb', '--no-follow-discovery',
                                  env_extra={'NXC_FAKE_WARNING_MODULE':'1'})
        self.assertEqual(result.returncode, 0, result.stderr)
        decisions = json.loads((self.out/'module-applicability.json').read_text())
        spooler = next(d for d in decisions if d['module'] == 'spooler')
        self.assertEqual(spooler['status'], 'attempted-unconfirmed')
        self.assertFalse(spooler['callback_confirmed'])

    def test_module_options_log_does_not_confirm_callback(self):
        result = self.run_wrapper('--protocols', 'mssql', '--no-follow-discovery',
                                  env_extra={'NXC_FAKE_OPTIONS_LOG': '1',
                                             'NXC_FAKE_SILENT_MODULE': '1'})
        self.assertEqual(result.returncode, 0, result.stderr)
        decisions = json.loads((self.out / 'module-applicability.json').read_text())
        enum_logins = next(d for d in decisions if d['target'] == '192.0.2.10' and
                           d['protocol'] == 'mssql' and d['module'] == 'enum_logins')
        self.assertEqual(enum_logins['status'], 'attempted-unconfirmed')
        self.assertFalse(enum_logins['callback_confirmed'])

    def test_resume_without_old_identity_does_not_reuse_admin_evidence(self):
        password = self.base / 'pass.txt'
        password.write_text('EXAMPLE-SECRET\n')
        first = self.run_wrapper('--protocols', 'smb', '--no-follow-discovery', '-u', 'auditor',
                                 '--password-file', str(password), '--credentials-only')
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertTrue(any(e['relation'] == 'AdminTo' for e in self.data()['analysis']['edges']))
        second = self.run_wrapper('--protocols', 'smb', '--no-follow-discovery', '--resume')
        self.assertEqual(second.returncode, 0, second.stderr)
        data = self.data()
        self.assertFalse(any(e['relation'] == 'AdminTo' for e in data['analysis']['edges']))
        old = [r for r in data['checks'] if r['identity'].startswith('supplied')]
        self.assertTrue(old)
        self.assertTrue(all(r.get('historical') for r in old))
        self.assertGreater(json.loads((self.out/'summary.json').read_text())['historical_checks'], 0)
        third = self.run_wrapper('--analyze-only')
        self.assertEqual(third.returncode, 0, third.stderr)
        self.assertFalse(any(e['relation'] == 'AdminTo' for e in self.data()['analysis']['edges']))

    def test_validated_kerberos_fallback_and_clock_diagnostic(self):
        password = self.base / 'pass.txt'
        password.write_text('EXAMPLE-SECRET\n')
        result = self.run_wrapper('--protocols', 'smb', '--no-follow-discovery', '-u', 'auditor',
                                  '--password-file', str(password), '--credentials-only',
                                  env_extra={'NXC_FAKE_NTLM_DISABLED':'1'})
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertTrue(any('-k' in c and c[1].casefold() == 'dc01.example.test' for c in calls))
        contexts = self.data()['hosts']['192.0.2.10']['capabilities']['smb']['445']
        self.assertTrue(any(c['method'] == 'kerberos' for c in contexts))
        result = self.run_wrapper('--protocols', 'smb', '--no-follow-discovery', '-u', 'auditor',
                                  '--password-file', str(password), '--credentials-only', '--resume',
                                  env_extra={'NXC_FAKE_NTLM_DISABLED':'1', 'NXC_FAKE_CLOCK_SKEW':'1'})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(any(c.get('auth_diagnostic') == 'clock-skew' for c in self.data()['checks']))

    def test_every_detected_ssh_endpoint_and_unsupported_service(self):
        result = self.run_wrapper('--nmap', '--nmap-bin', str(FAKE_NMAP), '--no-follow-discovery',
                                  '--profile', 'quick', env_extra={'NXC_FAKE_CUSTOM_PORTS':'1'})
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertEqual({c[c.index('--port')+1] for c in calls if c[0] == 'ssh'}, {'22', '2222'})
        data = self.data()
        self.assertTrue(any(c.get('endpoint_port') == 2222 for c in data['checks']))
        self.assertTrue(any(s['name'] == 'redis' for s in data['hosts']['192.0.2.10']['unsupported_services']))
        self.assertIn('TCP/6379 redis', (self.out/'summary.md').read_text())

    def test_automatic_fallback_requires_validated_mapping(self):
        password = self.base / 'pass.txt'
        password.write_text('EXAMPLE-SECRET\n')
        result = self.run_wrapper('--protocols', 'smb', '--profile', 'quick', '--no-follow-discovery',
                                  '--no-apply-hosts', '-u', 'auditor', '--password-file', str(password),
                                  '--credentials-only', env_extra={'NXC_FAKE_NTLM_DISABLED':'1'})
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertFalse(any('-k' in c for c in calls))
        self.assertTrue(any(c['check'] == 'kerberos-fallback' and c['status'] == 'skipped' for c in self.data()['checks']))

    def test_ip_only_banner_preserves_observed_nmap_names(self):
        result = self.run_wrapper('--nmap', '--nmap-bin', str(FAKE_NMAP), '--protocols', 'smb',
                                  '--profile', 'quick', '--no-follow-discovery', env_extra={'NXC_FAKE_IP_BANNER':'1'})
        self.assertEqual(result.returncode, 0, result.stderr)
        info = self.data()['hosts']['192.0.2.10']
        self.assertEqual(info['fqdn'], 'dc01.example.test')
        self.assertEqual(info['domain'], 'example.test')
        self.assertEqual(info['hosts_validation'], 'validated')

    def test_custom_schema_discovery_and_selected_attributes(self):
        result = self.run_wrapper('--protocols', 'ldap', '--no-follow-discovery', '--ldap-attribute', 'extensionAttribute1')
        self.assertEqual(result.returncode, 0, result.stderr)
        info = self.data()['hosts']['192.0.2.10']
        self.assertEqual(info['custom_attributes_requested'], ['extensionAttribute1', 'cascadeLegacyPwd'])
        checks = self.data()['checks']
        self.assertTrue(any(c['check'] == 'ldap-custom-values' and c['status'] == 'completed' for c in checks))
        self.assertTrue(any('cascadeLegacyPwd' in h['evidence'] and 'unverified' in h['title'] for h in self.data()['review_items']))
        self.assertNotIn('Zml4dHVyZS1vbmx5', result.stdout)
        self.assertNotIn('Zml4dHVyZS1vbmx5', (self.out/'events.jsonl').read_text())

    def test_resume_rechecks_changed_access_and_old_state(self):
        self.assertEqual(self.run_wrapper('--protocols', 'smb', '--profile', 'quick', '--no-follow-discovery').returncode, 0)
        data = self.data()
        data['hosts']['192.0.2.10']['access']['smb'].pop('endpoints')
        (self.out/'results.json').write_text(json.dumps(data))
        result = self.run_wrapper('--protocols', 'smb', '--profile', 'quick', '--no-follow-discovery', '--resume',
                                  env_extra={'NXC_FAKE_NEW_SHARE':'1'})
        self.assertEqual(result.returncode, 0, result.stderr)
        shares = next(c for c in self.data()['checks'] if c['check'] == 'shares')
        self.assertIn('NewAccess', (self.out/shares['log']).read_text())
        historic = list((self.out/'history').rglob(Path(shares['log']).name))
        self.assertTrue(historic)
        self.assertNotIn('NewAccess', historic[0].read_text())
        metadata = json.loads(historic[0].with_suffix('.json').read_text())
        self.assertEqual(self.out / metadata['log'], historic[0])

    def test_winrm_and_sql_capabilities_do_not_claim_smb_admin(self):
        password = self.base / 'pass.txt'
        password.write_text('EXAMPLE-SECRET\n')
        result = self.run_wrapper('--protocols', 'winrm,mssql', '--no-follow-discovery', '-u', 'auditor',
                                  '--password-file', str(password), '--credentials-only')
        self.assertEqual(result.returncode, 0, result.stderr)
        info = self.data()['hosts']['192.0.2.10']
        for protocol, capability in [('winrm','winrm-access'), ('mssql','sql-sysadmin-indicator')]:
            self.assertFalse(info['access'][protocol]['confirmed_admin'])
            for contexts in info['capabilities'][protocol].values():
                self.assertEqual(contexts[0]['capability'], capability)
                self.assertFalse(contexts[0]['local_admin_evidence'])

    def test_adaptive_inventory_and_html(self):
        result = self.run_wrapper("--share-content")
        self.assertEqual(result.returncode, 0, result.stderr)
        data = self.data()
        self.assertIn("ws01.example.test", data["discovered_hosts"])
        names = {u["username"] for u in data["users"]}
        self.assertTrue({"alice", "svc_sql"}.issubset(names))
        self.assertNotIn("Domain Admins", names)
        self.assertNotIn("DC01$", names)
        checks = {r["check"] for r in data["checks"]}
        self.assertIn("recursive-domain-admins", checks)
        self.assertTrue(any(k.startswith("adcs-templates-") for k in checks))
        self.assertTrue(any(k.startswith("share-content-") for k in checks))
        self.assertNotIn("<script>alert('fixture')</script>", (self.out / "report.html").read_text())
        self.assertIn("&lt;script&gt;", (self.out / "report.html").read_text())
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertFalse(any("DOWNLOAD_FLAG=False" in call for call in calls))
        self.assertFalse(any("ldap-checker" in call for call in calls))
        self.assertEqual((self.out / "results.json").stat().st_mode & 0o077, 0)

    def test_share_metadata_feeds_offline_workbook_inspection(self):
        result = self.run_wrapper('--protocols', 'smb', '--no-follow-discovery', '--download-matches',
                                  env_extra={'NXC_FAKE_XLSX':'1'})
        self.assertEqual(result.returncode, 0, result.stderr)
        analysis = self.data()['analysis']
        workbook = next(x for x in analysis['loot'] if x.get('inspection', {}).get('format') == 'xlsx')
        self.assertTrue(workbook['path'].endswith('.xlsx'))
        self.assertGreater(workbook['secret_candidates'], 0)
        candidates = [x for x in analysis['secret_candidates'] if x['loot_id'] == workbook['id']]
        self.assertIn('xl/sharedStrings.xml', candidates[0]['section'])
        self.assertFalse(candidates[0]['automatically_authenticated'])
        self.assertIn('xlsx · inspected', (self.out/'analysis.html').read_text())

    def test_secret_redaction_and_admin_checks(self):
        password = self.base / "pass.txt"
        password.write_text("EXAMPLE-SECRET-DO-NOT-LOG\n")
        result = self.run_wrapper("-u", "auditor", "--password-file", str(password), "--credentials-only", "--tickets")
        self.assertEqual(result.returncode, 0, result.stderr)
        for file in self.out.rglob("*"):
            if file.is_file():
                self.assertNotIn("EXAMPLE-SECRET-DO-NOT-LOG", file.read_text(errors="replace"), str(file))
        data = self.data()
        self.assertTrue(any(r["check"] == "interactive-sessions" and r["status"] == "completed" for r in data["checks"]))
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        secret_paths = {call[call.index("-p")+1] for call in calls if "-p" in call}
        self.assertTrue(secret_paths)
        self.assertTrue(all(not Path(p).exists() for p in secret_paths))

    def test_guest_users_feed_unauthenticated_asrep(self):
        result = self.run_wrapper("--tickets", env_extra={"NXC_FAKE_GUEST_ONLY": "1"})
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        asrep = [c for c in calls if "--asreproast" in c]
        self.assertEqual(len(asrep), 1)
        userfile = Path(asrep[0][asrep[0].index("-u")+1])
        self.assertEqual(set(userfile.read_text().splitlines()), {"alice", "svc_sql"})
        self.assertFalse(any("--kerberoasting" in c for c in calls))

    def test_old_flags_and_removed_modules(self):
        result = self.run_wrapper("--profile", "standard", "--control-checks", env_extra={"NXC_FAKE_OLD": "1"})
        self.assertEqual(result.returncode, 0, result.stderr)
        checks = self.data()["checks"]
        self.assertTrue(any(r["check"] == "ous" and r["status"] == "unsupported" for r in checks))
        self.assertTrue(any(r["check"] == "ldap-signing" and r["status"] == "unsupported" for r in checks))
        self.assertFalse(any(r["status"] == "error" for r in checks))

    def test_auth_failure_stops_supplied_identity(self):
        password = self.base / "pass.txt"
        password.write_text("INVALID\n")
        result = self.run_wrapper("-u", "auditor", "--password-file", str(password), "--credentials-only")
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        attempted = [c[0] for c in calls if "-u" in c]
        self.assertEqual(set(attempted), {"smb", "ldap", "mssql", "rdp", "ssh", "ftp", "vnc", "winrm", "wmi"})
        self.assertEqual(len(attempted), len(set(attempted)))
        self.assertTrue(any(r["status"] == "auth-failed" for r in self.data()["checks"]))

    def test_timeout_records_partial_output(self):
        result = self.run_wrapper("--timeout", "1", env_extra={"NXC_FAKE_TIMEOUT": "1"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(any(r["check"] == "sccm" and r["status"] == "timeout" and r.get("log") for r in self.data()["checks"]))

    def test_resume_reprobes_authentication(self):
        first = self.run_wrapper()
        self.assertEqual(first.returncode, 0, first.stderr)
        self.calls.write_text("")
        resumed = self.run_wrapper("--resume")
        self.assertEqual(resumed.returncode, 0, resumed.stderr)
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertTrue(any("-u" in c and "--users" not in c for c in calls))
        self.assertTrue(any("--users" in c for c in calls))
        self.assertTrue(list((self.out / 'history').rglob('*.log')))

    def test_different_supplied_account_gets_new_resume_checks(self):
        password = self.base / "pass.txt"
        password.write_text("EXAMPLE-SECRET\n")
        first = self.run_wrapper("-u", "auditor", "--password-file", str(password), "--credentials-only")
        self.assertEqual(first.returncode, 0, first.stderr)
        self.calls.write_text("")
        second = self.run_wrapper("-u", "newauditor", "--password-file", str(password), "--credentials-only", "--resume")
        self.assertEqual(second.returncode, 0, second.stderr)
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertTrue(any("--users" in c and c[c.index("-u")+1] == "newauditor" for c in calls))

    def test_profile_doctor_state_and_exclusions(self):
        state_log=self.base/'state.log'
        result=self.run_wrapper('--profile','quick','--exclude','192.0.2.10',env_extra={'NXC_FAKE_STATE_LOG':str(state_log)})
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertFalse(self.calls.exists())
        self.assertTrue(any(r['status']=='excluded' for r in self.data()['checks']))
        self.assertEqual((self.out/'scanned-targets.txt').read_text().strip(),'')
        self.assertTrue((self.out/'nxc-state').is_dir())
        doctor=self.run_wrapper('--resume','--doctor')
        self.assertEqual(doctor.returncode,0,doctor.stderr)
        self.assertTrue((self.out/'doctor.json').is_file())
        self.assertFalse(self.calls.exists())

    def test_resume_invalidates_changed_parameters_and_expired_cache(self):
        self.assertEqual(self.run_wrapper('--profile','quick','--share-content','--depth','1').returncode,0)
        self.calls.write_text('')
        result=self.run_wrapper('--profile','quick','--share-content','--depth','2','--resume')
        self.assertEqual(result.returncode,0,result.stderr)
        calls=[json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertTrue(any('--spider' in c and c[c.index('--depth')+1]=='2' for c in calls))
        self.calls.write_text('')
        result=self.run_wrapper('--profile','quick','--resume','--cache-max-age-hours','0')
        self.assertEqual(result.returncode,0,result.stderr)
        calls=[json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertTrue(any('--users' in c for c in calls))

    def test_oversize_download_is_quarantined_and_not_triaged(self):
        result=self.run_wrapper('--profile','quick','--download-matches','--max-file-bytes','128','--max-matches','1',env_extra={'NXC_FAKE_OVERSIZE':'1'})
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertTrue(any(r['status']=='artifact-oversize' for r in self.data()['checks']))
        self.assertTrue(list((self.out/'quarantine').glob('*')))
        self.assertFalse(self.data()['analysis']['secret_candidates'])

    def test_deep_profile_imports_generated_relative_bloodhound_archive(self):
        state_log=self.base/'state.log'
        result=self.run_wrapper('--profile','deep','--path-from','EXAMPLE\\auditor',env_extra={'NXC_FAKE_STATE_LOG':str(state_log)})
        self.assertEqual(result.returncode,0,result.stderr)
        data=self.data()
        self.assertTrue(data['analysis']['imports'])
        self.assertTrue(data['analysis']['paths'])
        self.assertTrue(any(f['category']=='ldap-protection' for f in data['analysis']['findings']))
        self.assertEqual(set(state_log.read_text().splitlines()),{str(self.out/'nxc-state')})

    def test_dry_run_makes_no_target_calls(self):
        result = self.run_wrapper("--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.calls.exists())
        self.assertTrue(all(r["status"] in ("planned", "skipped", "unsupported") for r in self.data()["checks"]))

    def test_bounded_matched_file_reads(self):
        result = self.run_wrapper("--download-matches", "--max-matches", "1")
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        # One bounded match per identity/host pass, including DNS-discovered hosts.
        downloads = [call for call in calls if "--get-file" in call]
        scanned = (self.out / "scanned-targets.txt").read_text().splitlines()
        self.assertEqual(len(downloads), len(scanned))
        self.assertEqual(len({(call[0], call[1]) for call in downloads}), len(scanned))
        self.assertTrue(any("Secret-like content in matched file" in h["title"] for h in self.data()["review_items"]))

    def test_protocol_wide_no_credential_enumeration_and_modules(self):
        result = self.run_wrapper("--no-follow-discovery")
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        protocols = {call[0] for call in calls}
        self.assertEqual(protocols, {"smb", "ldap", "mssql", "rdp", "ssh", "ftp", "nfs", "vnc", "winrm", "wmi"})
        self.assertTrue(any(call[0] == "ftp" and "--ls" in call for call in calls))
        self.assertTrue(any(call[0] == "nfs" and "--enum-shares" in call for call in calls))
        self.assertTrue(any(call[0] == "mssql" and "--database" in call for call in calls))
        self.assertTrue(any(call[0] == "wmi" and "--wmi-query" in call for call in calls))
        self.assertTrue(any(call[0] == "mssql" and "enum_logins" in call for call in calls))
        inventory = json.loads((self.out / "module-inventory.json").read_text())
        self.assertTrue(any(m["name"] == "enum_logins" and m["coverage"] == "automatic-safe" for m in inventory))

    def test_adaptive_one_ip_uses_evidence_for_dns_recursion(self):
        result = self.run_wrapper("--profile", "adaptive", "--max-hosts", "3")
        self.assertEqual(result.returncode, 0, result.stderr)
        data = self.data()
        self.assertIn("app01.example.test", data["discovered_hosts"])
        self.assertNotIn("external.invalid", data["discovered_hosts"])
        self.assertIn("app01.example.test", (self.out / "scanned-targets.txt").read_text())
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertTrue(any("get-network" in c and "ONLY_HOSTS=true" in c for c in calls))
        inventory = json.loads((self.out / "module-inventory.json").read_text())
        self.assertTrue(any(not m["options_inspected"] for m in inventory))
        self.assertTrue((self.out / "network-names").is_dir())

    def test_module_applicability_explains_execution_and_policy(self):
        result = self.run_wrapper("--no-follow-discovery", "--max-hosts", "1", "--profile", "adaptive")
        self.assertEqual(result.returncode, 0, result.stderr)
        decisions = json.loads((self.out / "module-applicability.json").read_text())
        def decision(protocol, name):
            return next(d for d in decisions if d["target"] == "192.0.2.10"
                        and d["protocol"] == protocol and d["module"] == name)
        self.assertEqual(decision("mssql", "enum_logins")["status"], "attempted")
        self.assertEqual(decision("smb", "spider_plus")["status"], "manual-review")
        self.assertEqual(decision("smb", "bitlocker")["status"], "not-applicable")
        self.assertIn("administrator", decision("smb", "bitlocker")["reason"])
        self.assertEqual(decision("ldap", "ldap-checker")["status"], "unavailable")
        self.assertEqual(sum(self.data()["module_applicability_summary"].values()), len(decisions))

    def test_default_full_enumeration_and_kerberos_name_bootstrap(self):
        hosts_file = self.base / "hosts"
        hosts_file.write_text("127.0.0.1 localhost\n")
        password = self.base / "password"
        password.write_text("test-only\n")
        krb_log = self.base / "krb-config-path"
        result = self.run_wrapper("--no-follow-discovery", "--apply-hosts", "--system-hosts-file",
                                  str(hosts_file), "--kerberos", "-u", "auditor", "--password-file",
                                  str(password), env_extra={"NXC_FAKE_KRB5_LOG": str(krb_log)})
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertTrue(any("--generate-hosts-file" in c for c in calls))
        self.assertIn("--generate-hosts-file", calls[0])
        self.assertTrue(any("--generate-krb5-file" in c for c in calls))
        self.assertFalse(any("--computers" in c and c[0] == "smb" for c in calls))
        self.assertTrue(any("--computers" in c and c[0] == "ldap" for c in calls))
        self.assertTrue(any(c[0] == "smb" and "--spider" in c and c[c.index("--spider") + 1] == "*" and
                            "--depth" in c and c[c.index("--depth") + 1] == "3" for c in calls))
        self.assertTrue(any("--reg-sessions" in c and c[0] == "smb" for c in calls))
        self.assertTrue(any("--query" in c and c[0] == "mssql" for c in calls))
        self.assertTrue(any(c[1].casefold() == "dc01.example.test" and "-k" in c for c in calls))
        self.assertTrue(any("--kdcHost" in c for c in calls if "-k" in c))
        self.assertEqual(krb_log.read_text(), str(self.out / "krb5.generated.conf"))
        self.assertIn("192.0.2.10 dc01.example.test dc01 example.test # nxc-enum", hosts_file.read_text().casefold())
        self.assertEqual(self.data()["hosts"]["192.0.2.10"]["hosts_validation"], "validated")
        self.assertTrue((self.out / "hosts.suggested").is_file())
        inventory = json.loads((self.out / "module-inventory.json").read_text())
        self.assertTrue(all(m["options_inspected"] for m in inventory))
        coverage = json.loads((self.out / "flag-coverage.json").read_text())
        self.assertTrue(any(c["protocol"] == "smb" and c["flag"] == "--computers" and
                            c["classification"] == "deprecated-upstream" for c in coverage))
        events = [json.loads(line) for line in (self.out / "events.jsonl").read_text().splitlines()]
        started = next(i for i, e in enumerate(events) if e['type'] == 'check_started' and e.get('check') == 'ldap-users')
        output = next(i for i, e in enumerate(events) if e['type'] == 'output' and e.get('check') == 'ldap-users')
        finished = next(i for i, e in enumerate(events) if e['type'] == 'check_finished' and e.get('check') == 'ldap-users')
        self.assertLess(started, output)
        self.assertLess(output, finished)
        self.assertTrue(any(e['type'] == 'user' for e in events))
        self.assertTrue(any(e['type'] == 'secret_candidate' for e in events))
        self.assertTrue(json.loads((self.out / 'live-map.json').read_text())['final'])
        self.assertEqual(events[-1]['type'], 'run_finished')
        self.assertTrue(any(e['type'] == 'module_decision' for e in events))
        for module, action in [('wdigest', 'ACTION=check'), ('tombstone', 'ACTION=query'), ('mssql_priv', 'ACTION=enum_priv')]:
            self.assertTrue(any('-M' in c and module in c and action in c for c in calls), module)
        self.assertFalse(any(any(x in c for x in ['ACTION=enable', 'ACTION=restore', 'ACTION=privesc']) for c in calls))

    def test_ldaps_only_endpoint_is_selected_automatically(self):
        result = self.run_wrapper('--nmap', '--nmap-bin', str(FAKE_NMAP), '--protocols', 'ldap',
                                  '--no-follow-discovery', env_extra={'NXC_FAKE_LDAPS_ONLY': '1'})
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        target_calls = [c for c in calls if c[0] == 'ldap' and '-h' not in c and '-L' not in c and '--options' not in c]
        self.assertTrue(target_calls)
        self.assertTrue(all('--port' in c and c[c.index('--port') + 1] == '636' for c in target_calls))

    def test_winrm_https_endpoint_is_selected_automatically(self):
        result = self.run_wrapper('--nmap', '--nmap-bin', str(FAKE_NMAP), '--protocols', 'winrm',
                                  '--no-follow-discovery', env_extra={'NXC_FAKE_WINRM_HTTPS_ONLY': '1'})
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        target_calls = [c for c in calls if c[0] == 'winrm' and '-h' not in c and '-L' not in c and '--options' not in c]
        self.assertTrue(target_calls)
        self.assertTrue(all(c[c.index('--port') + 1] == '5986' for c in target_calls))
        self.assertTrue(all(c[c.index('--check-proto') + 1] == 'https' for c in target_calls))

    def test_rdp_nla_discovery_runs_without_accepted_login(self):
        password = self.base / 'password'
        password.write_text('INVALID\n')
        result = self.run_wrapper('--nmap', '--nmap-bin', str(FAKE_NMAP), '--protocols', 'rdp',
                                  '--no-follow-discovery', '--credentials-only', '-u', 'auditor',
                                  '--password-file', str(password), env_extra={'NXC_FAKE_RDP_ONLY': '1'})
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        nla = [c for c in calls if c[0] == 'rdp' and '--nla-screenshot' in c]
        self.assertEqual(len(nla), 1)
        self.assertNotIn('-u', nla[0])
        checks = [r for r in self.data()['checks'] if r['check'] == 'rdp-nla']
        self.assertEqual(len(checks), 1)
        self.assertIn(checks[0]['status'], ('completed', 'completed-with-messages'))
        self.assertTrue(any(path.endswith('nla.png') for path in checks[0].get('artifacts', [])))
        self.assertTrue(any(item['path'].endswith('nla.png') for item in self.data()['analysis']['loot']))

    def test_admin_modules_use_only_confirmed_admin_identity(self):
        password = self.base / 'password'
        password.write_text('test-only\n')
        result = self.run_wrapper('--protocols', 'smb', '--no-follow-discovery', '-u', 'auditor',
                                  '--password-file', str(password))
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        bitlocker = [c for c in calls if '-M' in c and c[c.index('-M') + 1] == 'bitlocker']
        self.assertEqual(len(bitlocker), 1)
        self.assertEqual(bitlocker[0][bitlocker[0].index('-u') + 1], 'auditor')
        spooler = [c for c in calls if '-M' in c and c[c.index('-M') + 1] == 'spooler']
        self.assertTrue(spooler)
        self.assertTrue(all(c[c.index('-u') + 1] == 'auditor' for c in spooler))
        decisions = json.loads((self.out / 'module-applicability.json').read_text())
        bitlocker_decision = next(d for d in decisions if d['target'] == '192.0.2.10' and
                                  d['protocol'] == 'smb' and d['module'] == 'bitlocker')
        self.assertTrue(bitlocker_decision['requires_admin'])
        self.assertEqual(bitlocker_decision['status'], 'attempted')

    def test_low_privilege_context_never_runs_admin_only_modules(self):
        result = self.run_wrapper('--protocols', 'smb', '--no-follow-discovery')
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        modules = {c[c.index('-M') + 1] for c in calls if '-M' in c}
        self.assertIn('spooler', modules)
        self.assertNotIn('bitlocker', modules)
        self.assertNotIn('wcc', modules)
        self.assertNotIn('sccm-recon6', modules)
        checks = self.data()['checks']
        self.assertTrue(any(r['check'].startswith('module-bitlocker') and r['status'] == 'skipped' and
                            'administrator' in r['reason'] for r in checks))
        decisions = json.loads((self.out / 'module-applicability.json').read_text())
        sccm = next(d for d in decisions if d['target'] == '192.0.2.10' and
                    d['protocol'] == 'smb' and d['module'] == 'sccm-recon6')
        self.assertEqual(sccm['status'], 'manual-review')
        self.assertIn('outside the wrapper-managed target queue', sccm['reason'])

    def test_success_without_module_prefix_is_not_reported_as_confirmed_execution(self):
        result = self.run_wrapper('--protocols', 'mssql', '--no-follow-discovery',
                                  env_extra={'NXC_FAKE_SILENT_MODULE': '1'})
        self.assertEqual(result.returncode, 0, result.stderr)
        checks = self.data()['checks']
        self.assertTrue(any(r['check'].startswith('module-enum_logins') and
                            r['status'] == 'attempted-no-module-output' for r in checks))
        decisions = json.loads((self.out / 'module-applicability.json').read_text())
        enum_logins = next(d for d in decisions if d['target'] == '192.0.2.10' and
                           d['protocol'] == 'mssql' and d['module'] == 'enum_logins')
        self.assertEqual(enum_logins['status'], 'attempted-unconfirmed')

    def test_autonomous_ftp_followup_and_depth_bound(self):
        result = self.run_wrapper('--protocols', 'ftp', '--no-follow-discovery', '--depth', '2',
                                  env_extra={'NXC_FAKE_FTP_TREE': '1'})
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        paths = [c[c.index('--ls') + 1] for c in calls if '--ls' in c]
        self.assertEqual(paths, ['.', './Documents', './Documents/Nested Folder'])
        self.assertTrue(any(h['title'] == 'FTP directory inventory truncated' for h in self.data()['review_items']))
        events = [json.loads(line) for line in (self.out / 'events.jsonl').read_text().splitlines()]
        self.assertEqual(sum(e['type'] == 'directory_queued' for e in events), 2)

    def test_vnc_no_auth_banner_establishes_access_context(self):
        result = self.run_wrapper('--protocols', 'vnc', '--no-follow-discovery',
                                  env_extra={'NXC_FAKE_VNC_NO_AUTH': '1'})
        self.assertEqual(result.returncode, 0, result.stderr)
        host = self.data()['hosts']['192.0.2.10']
        self.assertEqual(host['vnc_no_auth'], 'True')
        self.assertEqual(host['access']['vnc']['accepted_contexts'], ['null'])

    def test_dc_names_feed_recursive_inventory_without_trust_scope_expansion(self):
        result = self.run_wrapper('--protocols', 'ldap', '--max-hosts', '3',
                                  env_extra={'NXC_FAKE_DC_LIST': '1'})
        self.assertEqual(result.returncode, 0, result.stderr)
        names = self.data()['discovered_hosts']
        self.assertIn('dc02.example.test', names)
        self.assertIn('dc01.other.test', names)
        self.assertNotIn('missing.example.test', names)
        scanned = (self.out / 'scanned-targets.txt').read_text().splitlines()
        self.assertEqual(scanned, ['192.0.2.10', 'app01.example.test', 'dc02.example.test'])
        self.assertNotIn('dc01.other.test', scanned)

    def test_missing_supplied_secret_fails_without_prompt(self):
        result = self.run_wrapper('-u', 'auditor', '--no-follow-discovery')
        self.assertEqual(result.returncode, 2)
        self.assertIn('does not prompt', result.stderr)
        self.assertFalse(self.calls.exists())

    def test_sql_database_names_feed_bounded_table_inventory(self):
        result = self.run_wrapper("--no-follow-discovery", "--max-databases", "1", "--protocols", "mssql",
                                  env_extra={"NXC_FAKE_DATABASES": "1"})
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        tables = [c for c in calls if "--database" in c and c[c.index("--database") + 1:] == ["master"]]
        self.assertEqual(len(tables), 1)
        self.assertTrue(any("Database table inventory truncated" == h["title"] for h in self.data()["review_items"]))

    def test_invalid_generated_kerberos_config_is_not_used(self):
        password = self.base / "password"
        password.write_text("test-only\n")
        krb_log = self.base / "krb-config-path"
        result = self.run_wrapper("--no-follow-discovery", "--protocols", "smb", "-k",
                                  "-u", "auditor", "--password-file", str(password),
                                  env_extra={"NXC_FAKE_BAD_KRB5": "1", "NXC_FAKE_KRB5_LOG": str(krb_log)})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotEqual(krb_log.read_text(), str(self.out / "krb5.generated.conf"))
        self.assertEqual(self.data()["hosts"]["192.0.2.10"]["krb5_validation"],
                         "invalid realm or KDC in generated file")

    def test_failed_hosts_install_withholds_kerberos_authentication(self):
        password = self.base / "password"
        password.write_text("test-only\n")
        result = self.run_wrapper("--no-follow-discovery", "--system-hosts-file", str(self.base),
                                  "-u", "auditor", "--password-file", str(password), "-k")
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertFalse(any("-k" in c for c in calls))
        self.assertTrue(any("--generate-hosts-file" in c for c in calls))
        self.assertTrue(any(c["check"] == "auth-probe" and c["status"] == "skipped" and
                            "FQDN resolution" in c["reason"] for c in self.data()["checks"]))

    def test_full_module_option_audit_remains_available(self):
        result = self.run_wrapper("--doctor", "--inspect-all-module-options")
        self.assertEqual(result.returncode, 0, result.stderr)
        inventory = json.loads((self.out / "module-inventory.json").read_text())
        self.assertTrue(inventory)
        self.assertTrue(all(m["options_inspected"] for m in inventory))

    def test_nmap_xml_feeds_protocols_and_host_facts(self):
        result = self.run_wrapper("--nmap", "--nmap-bin", str(FAKE_NMAP),
                                  "--max-hosts", "1", "--profile", "quick")
        self.assertEqual(result.returncode, 0, result.stderr)
        data = self.data()
        facts = data["hosts"]["192.0.2.10"]["nmap"]
        self.assertEqual(facts["open_ports"], [389, 445, 9999])
        self.assertEqual(data['hosts']['192.0.2.10']['unsupported_services'][0]['port'], 9999)
        self.assertIn("dc01.example.test", data["discovered_hosts"])
        self.assertEqual(facts["scripts"][0]["id"], "smb2-security-mode")
        self.assertEqual(data["action_trace"][0]["next_actions"], ["nxc:smb", "nxc:ldap"])
        self.assertTrue(any(c["check"] == "nmap-discovery" for c in data["checks"]))
        self.assertTrue((self.out / "nmap").is_dir())
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertEqual({c[0] for c in calls}, {"smb", "ldap"})
        self.assertFalse((self.out / "netexec-rdp-help.txt").exists())
        self.assertEqual(set(json.loads((self.out / "capabilities.json").read_text())), {"smb", "ldap"})
        summary = json.loads((self.out / "summary.json").read_text())
        self.assertEqual({row["protocol"] for row in summary["protocol_coverage"] if
                          row["checks"].get("completed")}, {"nmap", "smb", "ldap"})
        self.assertIn("Modules attempted / inventoried", (self.out / "summary.md").read_text())
        self.assertIn("summary.md", (self.out / "report.html").read_text())

    def test_closed_smb_does_not_inspect_or_run_smb(self):
        result = self.run_wrapper("--nmap", "--nmap-bin", str(FAKE_NMAP), "--no-follow-discovery",
                                  env_extra={"NXC_FAKE_NO_SMB": "1"})
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertEqual({c[0] for c in calls}, {"ldap"})
        self.assertEqual(set(json.loads((self.out / "capabilities.json").read_text())), {"ldap"})
        self.assertFalse((self.out / "hosts.suggested").exists())

    def test_short_password_preserves_account_inventory(self):
        password = self.base / "pass.txt"
        password.write_text("a\n")
        result = self.run_wrapper("-u", "auditor", "--password-file", str(password), "--credentials-only")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("alice", {u["username"] for u in self.data()["users"]})
        auth = [r for r in self.data()["checks"] if r["check"] == "auth-probe"]
        self.assertTrue(all(r["status"] == "completed" for r in auth))


if __name__ == "__main__":
    unittest.main()
