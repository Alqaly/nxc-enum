"""Live output privacy, split-byte decoding and provisional-map semantics."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from nxc_live import EventStream, LiveOutput


class LiveTests(unittest.TestCase):
    def test_split_bytes_redact_supplied_secret_and_preserve_discoveries(self):
        with tempfile.TemporaryDirectory() as temp:
            stream = EventStream(Path(temp), display=False)
            live = LiveOutput(stream, '192.0.2.10', 'ldap', 'ldap-users', 'logs/users.log',
                              lambda line: line.replace('private-value', '<supplied-secret>'))
            payload = 'álîce    2026-01-01 0 description password: private-value\n'.encode()
            for byte in payload:
                live(bytes([byte]))
            live.finish()
            text = stream.path.read_text()
            self.assertNotIn('private-value', text)
            events = [json.loads(line) for line in text.splitlines()]
            self.assertTrue(any(e['type'] == 'user' and e['name'] == 'álîce' for e in events))
            self.assertTrue(any(e['type'] == 'secret_candidate' for e in events))
            self.assertTrue(all(e['source'] == 'logs/users.log' for e in events))

    def test_group_rows_do_not_invent_membership_and_final_map_replaces_provisional(self):
        with tempfile.TemporaryDirectory() as temp:
            stream = EventStream(Path(temp), display=False)
            live = LiveOutput(stream, 'dc01.example.test', 'ldap', 'groups', 'logs/groups.log', lambda x: x)
            live(b'Domain Admins             2        privileged group\n')
            live(b'Empty Description Group             1\n')
            live.finish()
            events = [json.loads(line) for line in stream.path.read_text().splitlines()]
            self.assertEqual(next(e['members_reported'] for e in events if e['type'] == 'group'), 2)
            self.assertTrue(any(e['type'] == 'group' and e['name'] == 'Empty Description Group' for e in events))
            self.assertFalse(any(e['type'] == 'relationship' for e in events))
            stream.update_map({'nodes': [{'id': 'provisional'}], 'edges': []})
            stream.update_map({'nodes': [{'id': 'canonical'}], 'edges': []}, final=True)
            graph = json.loads((Path(temp) / 'live-map.json').read_text())
            self.assertEqual([n['id'] for n in graph['nodes']], ['canonical'])
            self.assertTrue(graph['final'])


if __name__ == '__main__':
    unittest.main()
