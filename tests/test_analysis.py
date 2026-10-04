"""Graph direction, incomplete evidence, offline import and loot integrity tests."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile
import sqlite3

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from nxc_analysis import Analysis, parse_share

SID = "S-1-5-21-100-200-300"


def bh_documents():
    # Classic collector-format schema: membership is stored on the group;
    # sessions are stored on the computer and point ComputerSID -> UserSID.
    def obj(number, name, **fields):
        return {"ObjectIdentifier": SID + "-" + str(number), "Properties": {"name": name}, **fields}
    return {
        "users.json": {"meta": {"type": "users", "version": 5}, "data": [obj(1101, "AUDITOR@EXAMPLE.TEST"), obj(1102, "ADMIN@EXAMPLE.TEST")]},
        "groups.json": {"meta": {"type": "groups", "version": 5}, "data": [
            obj(1201, "OPS@EXAMPLE.TEST", Members=[{"ObjectIdentifier": SID + "-1101", "ObjectType": "User"}]),
            obj(512, "DOMAIN ADMINS@EXAMPLE.TEST", Members=[{"ObjectIdentifier": SID + "-1102", "ObjectType": "User"}])]},
        "computers.json": {"meta": {"type": "computers", "version": 5}, "data": [
            obj(1301, "WS01.EXAMPLE.TEST", LocalAdmins={"Collected": True, "Results": [{"ObjectIdentifier": SID + "-1201", "ObjectType": "Group"}]},
                Sessions={"Collected": True, "Results": [{"ComputerSID": SID + "-1301", "UserSID": SID + "-1102"}]},
                Aces=[{"PrincipalSID": SID + "-1101", "PrincipalType": "User", "RightName": "GetChanges"}]),
            obj(1302, "WS02.EXAMPLE.TEST", AllowedToAct=[{"ObjectIdentifier": SID + "-1101", "ObjectType": "User"}])]}}


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.out = self.base / "run"
        self.out.mkdir()
        self.data = {"hosts": {"192.0.2.10": {"domain": "example.test", "hostname": "DC01"}}, "checks": [], "users": [], "review_items": []}
        self.archive = self.base / "bh.zip"
        with zipfile.ZipFile(self.archive, "w") as z:
            for name, doc in bh_documents().items():
                z.writestr(name, json.dumps(doc))

    def tearDown(self):
        self.tmp.cleanup()

    def build(self, **kwargs):
        return Analysis(self.out, self.data, imports=[str(self.archive)], starts=["EXAMPLE\\auditor"], **kwargs).build()

    def test_membership_admin_session_path_and_direction(self):
        data = self.build()
        self.assertEqual(len(data["paths"]), 1)
        path = data["paths"][0]
        edges = {e["id"]: e for e in data["edges"]}
        self.assertEqual([edges[e]["relation"] for e in path["edge_ids"]], ["MemberOf", "AdminTo", "HasSession", "MemberOf"])
        self.assertEqual(path["hops"], 4)
        self.assertTrue(any("Session type" in x for x in path["missing_prerequisites"]))
        rbcd = next(e for e in data["edges"] if e["relation"] == "AllowedToAct")
        self.assertTrue(rbcd["source"].endswith("auditor"))
        self.assertTrue(rbcd["target"].endswith("ws02.example.test"))
        self.assertFalse(any(e["relation"] in {"GetChanges", "DCSync"} for e in data["edges"]))

    def test_directory_relationship_query_builds_recursive_group_path(self):
        logs = self.out / "logs"
        logs.mkdir()
        body = """LDAP 192.0.2.10 389 DC01 [+] Response for object: CN=alice,DC=example,DC=test
LDAP 192.0.2.10 389 DC01 sAMAccountName alice
LDAP 192.0.2.10 389 DC01 distinguishedName CN=alice,DC=example,DC=test
LDAP 192.0.2.10 389 DC01 objectClass user
LDAP 192.0.2.10 389 DC01 memberOf CN=Ops,DC=example,DC=test
LDAP 192.0.2.10 389 DC01 [+] Response for object: CN=Ops,DC=example,DC=test
LDAP 192.0.2.10 389 DC01 sAMAccountName Ops
LDAP 192.0.2.10 389 DC01 distinguishedName CN=Ops,DC=example,DC=test
LDAP 192.0.2.10 389 DC01 objectClass group
LDAP 192.0.2.10 389 DC01 memberOf CN=Domain Admins,DC=example,DC=test
LDAP 192.0.2.10 389 DC01 [+] Response for object: CN=Domain Admins,DC=example,DC=test
LDAP 192.0.2.10 389 DC01 sAMAccountName Domain Admins
LDAP 192.0.2.10 389 DC01 distinguishedName CN=Domain Admins,DC=example,DC=test
LDAP 192.0.2.10 389 DC01 objectClass group
"""
        (logs / "relationships.log").write_text(body)
        self.data["checks"].append({"id": "directory1", "check": "directory-relationships", "target": "192.0.2.10",
                                    "protocol": "ldap", "identity": "null", "status": "completed",
                                    "time": "2026-10-01", "log": "logs/relationships.log"})
        data = Analysis(self.out, self.data, starts=["EXAMPLE.TEST\\alice"]).build()
        relations = [e for e in data["edges"] if e["relation"] == "MemberOf"]
        self.assertEqual(len(relations), 2)
        self.assertEqual(len(data["paths"]), 1)
        self.assertEqual(data["paths"][0]["hops"], 2)

    def test_multivalue_ldap_members_and_primary_group_are_preserved(self):
        logs = self.out / 'logs'
        logs.mkdir()
        rows = [
            'Response for object: CN=alice,DC=example,DC=test',
            'sAMAccountName alice', 'distinguishedName CN=alice,DC=example,DC=test',
            'objectSid ' + SID + '-1101', 'objectClass top', 'person', 'user',
            'primaryGroupID 513', 'memberOf CN=Ops,DC=example,DC=test', 'CN=Extra,DC=example,DC=test',
            'Response for object: CN=Ops,DC=example,DC=test',
            'sAMAccountName Ops', 'distinguishedName CN=Ops,DC=example,DC=test',
            'objectClass top', 'group', 'member CN=alice,DC=example,DC=test', 'CN=bob,DC=example,DC=test',
            'Response for object: CN=Domain Users,DC=example,DC=test',
            'sAMAccountName Domain Users', 'distinguishedName CN=Domain Users,DC=example,DC=test',
            'objectSid ' + SID + '-513', 'objectClass top', 'group']
        (logs / 'multi.log').write_text('\n'.join('LDAP 192.0.2.10 389 DC01 ' + r for r in rows))
        self.data['checks'].append({'id': 'multi', 'check': 'directory-relationships', 'target': '192.0.2.10',
                                   'protocol': 'ldap', 'identity': 'null', 'status': 'completed', 'log': 'logs/multi.log'})
        data = Analysis(self.out, self.data).build()
        membership = [e for e in data['edges'] if e['relation'] == 'MemberOf']
        self.assertEqual(len(membership), 3)
        primary = [e for e in data['edges'] if e['relation'] == 'PrimaryGroupMemberOf']
        self.assertEqual(len(primary), 1)
        node = next(n for n in data['nodes'] if n['id'] == primary[0]['target'])
        self.assertIn('domain users', node['label'].lower())
        ops = next(n for n in data['nodes'] if n['label'].lower().endswith('\\ops'))
        self.assertEqual(ops['kind'], 'Group')

    def test_depth_cap_and_no_fabricated_start(self):
        self.assertEqual(self.build(depth=3)["paths"], [])
        unknown = Analysis(self.out, self.data, imports=[str(self.archive)], starts=["EXAMPLE\\absent"]).build()
        self.assertEqual(unknown["paths"], [])
        self.assertTrue(any("not found" in w for w in unknown["warnings"]))

    def test_conflicting_sids_do_not_merge_by_display_name(self):
        a = Analysis(self.out, self.data)
        first = a.node("EXAMPLE\\sameuser", "User", SID + "-1001")
        second = a.node("SAMEUSER@EXAMPLE.TEST", "User", SID + "-1002")
        self.assertNotEqual(first, second)
        self.assertEqual(len(a.nodes), 2)
        self.assertTrue(any("Conflicting" in w for w in a.warnings))

    def test_share_names_with_spaces_preserve_access_columns(self):
        self.assertEqual(parse_share('SMB 192.0.2.10 445 DC01 Team Documents  READ,WRITE             shared team files'),('Team Documents','READ,WRITE'))
        self.assertEqual(parse_share('SYSVOL          READ                   policies'),('SYSVOL','READ'))
        self.assertIsNone(parse_share('Share           Permissions            Remark'))

    def test_failed_collection_results_do_not_create_edges(self):
        docs = bh_documents()
        computer = docs['computers.json']['data'][0]
        computer['Sessions']['Collected'] = False
        computer['Sessions']['FailureReason'] = 'AccessDenied'
        with zipfile.ZipFile(self.archive, 'w') as z:
            for name, doc in docs.items():
                z.writestr(name, json.dumps(doc))
        data = self.build()
        self.assertFalse(any(e['relation']=='HasSession' for e in data['edges']))
        self.assertFalse(data['paths'])
        self.assertTrue(any(q['state']=='failed' and q['failure_reason']=='AccessDenied' for q in data['collection_quality']))

    def test_modern_local_group_schema_and_membership_provenance(self):
        docs = bh_documents()
        computer = docs['computers.json']['data'][0]
        del computer['LocalAdmins']
        computer['LocalGroups'] = [{'ObjectIdentifier':SID+'-544','Name':'ADMINISTRATORS@WS01.EXAMPLE.TEST',
                                   'Collected':True,'Results':[{'ObjectIdentifier':SID+'-1201','ObjectType':'Group'}]}]
        with zipfile.ZipFile(self.archive,'w') as z:
            for name, doc in docs.items():
                z.writestr(name,json.dumps(doc))
        data=self.build()
        self.assertEqual(len(data['paths']),1)
        self.assertTrue(any(e['relation']=='MemberOfLocalGroup' and not e['traversable'] for e in data['edges']))
        admins=[e for e in data['edges'] if e['relation']=='AdminTo']
        self.assertEqual(admins[0]['evidence'][0]['local_group_id'], SID+'-544')

    def test_alternative_paths_and_goals_beyond_first_goal(self):
        a=Analysis(self.out,self.data,paths_per_goal=2)
        start=a.node('start','User'); left=a.node('left','Group'); right=a.node('right','Group')
        goal=a.node('goal','Group',highvalue=True); last=a.node('last','Group',highvalue=True)
        a.starts.add(start)
        for source,target in ((start,left),(start,right),(left,goal),(right,goal),(goal,last)):
            a.edge(source,target,'MemberOf',{'source':'fixture'})
        paths=a.paths()
        self.assertEqual(sum(p['goal']==goal for p in paths),2)
        self.assertEqual(sum(p['goal']==last for p in paths),2)

    def test_kerberos_auth_without_password_separator_is_a_start(self):
        logs=self.out/'logs';logs.mkdir()
        (logs/'cache.log').write_text('SMB 192.0.2.10 445 DC01 [+] example.test\\auditor (Pwn3d!)\n')
        self.data['checks'].append({'id':'cache1','check':'auth-probe','target':'192.0.2.10','protocol':'smb','identity':'supplied:cache','status':'completed','time':'2026-10-01','log':'logs/cache.log'})
        data=Analysis(self.out,self.data,imports=[str(self.archive)]).build()
        self.assertTrue(data['paths'])
        self.assertTrue(any(e['relation']=='AuthenticatedTo' for e in data['edges']))

    def test_database_metadata_omits_values_and_is_read_only(self):
        folder=self.out/'nxc-state'/'workspaces'/'default';folder.mkdir(parents=True)
        file=folder/'smb.db'
        with sqlite3.connect(file) as db:
            db.execute('CREATE TABLE users(id INTEGER,domain TEXT,username TEXT,password TEXT,credtype TEXT)')
            db.execute('CREATE TABLE hosts(id INTEGER,ip TEXT,hostname TEXT,domain TEXT)')
            db.execute('CREATE TABLE admin_relations(id INTEGER,userid INTEGER,hostid INTEGER)')
            db.execute("INSERT INTO users VALUES(1,'example.test','auditor','DO-NOT-EXPORT-SECRET','plaintext')")
            db.execute("INSERT INTO hosts VALUES(1,'192.0.2.20','WS01','example.test')")
            db.execute('INSERT INTO admin_relations VALUES(1,1,1)')
        before=hashlib.sha256(file.read_bytes()).hexdigest()
        data=self.build()
        self.assertEqual(len(data['credential_inventory']),1)
        self.assertEqual(data['credential_inventory'][0]['username'],'auditor')
        self.assertEqual(before,hashlib.sha256(file.read_bytes()).hexdigest())
        for filename in ('credential-inventory.json','analysis.html'):
            self.assertNotIn('DO-NOT-EXPORT-SECRET',(self.out/filename).read_text())

    def test_interactive_session_requires_a_real_row(self):
        logs = self.out / "logs"
        logs.mkdir()
        (logs / "sessions.log").write_text("SMB 192.0.2.10 445 DC01 [+] Enumerated qwinsta sessions\nSMB 192.0.2.10 445 DC01 SESSIONNAME USERNAME ID IPv4 Address STATE\nSMB 192.0.2.10 445 DC01 rdp-tcp#2 EXAMPLE\\admin 3 192.0.2.50 Active Unlocked\n")
        self.data["checks"].append({"id": "sessions1", "check": "interactive-sessions", "target": "192.0.2.10", "protocol": "smb", "identity": "supplied", "status": "completed", "time": "2026-10-01", "log": "logs/sessions.log"})
        data = self.build()
        observed = [e for e in data["edges"] if e["confidence"] == "interactive-session-observation"]
        self.assertEqual(len(observed), 1)
        self.assertTrue(observed[0]["source"].endswith("dc01.example.test"))
        self.assertEqual(observed[0]["evidence"][0]["session_state"], "Active")

    def test_loot_hash_provenance_and_redacted_candidate(self):
        folder = self.out / "matched-files"
        folder.mkdir()
        body = b'username=service\npassword=ACTUAL-SECRET-TEST\n'
        (folder / "config.bin").write_bytes(body)
        self.data["checks"].append({"id": "read1", "check": "read-match-1", "target": "192.0.2.10", "protocol": "smb", "identity": "supplied", "status": "completed", "time": "2026-10-01", "artifacts": ["matched-files/config.bin"]})
        data = self.build()
        loot = next(x for x in data["loot"] if x["path"] == "matched-files/config.bin")
        self.assertEqual(loot["sha256"], hashlib.sha256(body).hexdigest())
        self.assertEqual(loot["check_ids"], ["read1"])
        self.assertEqual(loot["secret_candidates"], 1)
        self.assertFalse(data["secret_candidates"][0]["automatically_authenticated"])
        for file in ("analysis.html", "secret-candidates.json", "loot.csv"):
            self.assertNotIn("ACTUAL-SECRET-TEST", (self.out / file).read_text())
        self.assertIn("ACTUAL-SECRET-TEST", (folder / "config.bin").read_text())

    def test_review_status_persists_and_html_escapes(self):
        logs = self.out / "logs"
        logs.mkdir()
        (logs / "banner.log").write_text("SMB 192.0.2.10 445 DC01 [*] (name:DC01) (domain:example.test) (signing:False)\n")
        self.data["checks"].append({"id": "banner1", "check": "banner", "target": "192.0.2.10", "protocol": "smb", "identity": "discovery", "status": "completed", "time": "2026-10-01", "log": "logs/banner.log"})
        finding = self.build()["findings"][0]
        reviews = self.base / "review.json"
        reviews.write_text(json.dumps({finding["id"]: {"status": "false-positive", "note": "<script>UNSAFE</script>"}}))
        updated = self.build(review_file=str(reviews))
        self.assertEqual(updated["findings"][0]["status"], "false-positive")
        self.assertNotIn("<script>UNSAFE</script>", (self.out / "analysis.html").read_text())
        self.assertEqual(self.build()["findings"][0]["status"], "false-positive")

    def test_zip_members_never_extracted_and_bad_input_is_rejected(self):
        with zipfile.ZipFile(self.archive, "a") as z:
            z.writestr("../escape.json", json.dumps({"data": [], "meta": {"type": "users"}}))
        self.build()
        self.assertFalse((self.out.parent / "escape.json").exists())
        invalid = self.base / "invalid.json"
        invalid.write_text('{')
        with self.assertRaises(ValueError):
            Analysis(self.out, self.data, imports=[str(invalid)]).build()

    def test_offline_cli_without_netexec_and_comparison(self):
        self.data["schema_version"] = 1
        (self.out / "results.json").write_text(json.dumps(self.data))
        args = [sys.executable, str(ROOT / "nxc_enum.py"), "--analyze-only", "-o", str(self.out), "--nxc", "/does/not/exist", "--import-bloodhound", str(self.archive), "--path-from", "EXAMPLE\\auditor"]
        result = subprocess.run(args, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        first = json.loads((self.out / "results.json").read_text())
        self.assertEqual(len(first["analysis"]["paths"]), 1)
        previous = self.base / "previous.json"
        previous.write_text(json.dumps(first))
        result = subprocess.run(args + ["--compare", str(previous)], capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        delta = json.loads((self.out / "delta.json").read_text())
        self.assertEqual(delta["paths"]["new_ids"], [])
        self.assertEqual(len(delta["paths"]["retained_ids"]), 1)


if __name__ == "__main__":
    unittest.main()
