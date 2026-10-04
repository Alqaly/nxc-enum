"""Resource limits and target-selection invariants; no network access."""
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from nxc_runtime import Scope, capture, verify_evidence
import hashlib


class RuntimeTests(unittest.TestCase):
    def test_child_cannot_wait_for_interactive_input(self):
        code = "import sys; assert sys.stdin.read() == ''; print('noninteractive')"
        output, status, expired, limited, _ = capture([sys.executable, '-c', code], None, os.environ.copy(), 2, 4096)
        self.assertEqual(status, 0, output)
        self.assertIn('noninteractive', output)
        self.assertFalse(expired)
        self.assertFalse(limited)

    def test_output_callback_runs_before_child_exits(self):
        with tempfile.TemporaryDirectory() as temp:
            acknowledgement = Path(temp) / 'seen'
            code = ("import pathlib,sys,time; p=pathlib.Path(sys.argv[1]); "
                    "print('first',flush=True); deadline=time.monotonic()+2\n"
                    "while not p.exists() and time.monotonic()<deadline: time.sleep(.01)\n"
                    "assert p.exists(), 'parent did not stream output before exit'\n"
                    "print('released',flush=True)")
            chunks = []
            def observe(chunk):
                chunks.append(chunk)
                if b'first' in b''.join(chunks):
                    acknowledgement.touch()
            text, code, expired, limited, _ = capture(
                [sys.executable, '-c', code, str(acknowledgement)], None, os.environ.copy(),
                5, 4096, on_chunk=observe)
            self.assertEqual(code, 0, text)
            self.assertIn('released', text)
            self.assertFalse(expired)
            self.assertFalse(limited)

    def test_output_is_bounded_and_child_is_stopped(self):
        code = "import sys,time;sys.stdout.write('x'*1000000);sys.stdout.flush();time.sleep(30)"
        started = time.monotonic()
        text, _, expired, limited, _ = capture([sys.executable, '-c', code], None, os.environ.copy(), 5, 2048)
        self.assertEqual(len(text), 2048)
        self.assertEqual(limited, 'output')
        self.assertFalse(expired)
        self.assertLess(time.monotonic()-started, 4)

    def test_download_growth_is_monitored(self):
        with tempfile.TemporaryDirectory() as temp:
            file = Path(temp)/'download.bin'
            code = "from pathlib import Path;import sys,time;Path(sys.argv[1]).write_bytes(b'x'*100000);time.sleep(30)"
            _, _, expired, limit, _ = capture([sys.executable, '-c', code, str(file)], None, os.environ.copy(), 5, 4096, file, 1024)
            self.assertEqual(limit, 'artifact-size')
            self.assertFalse(expired)

    def test_scope_cidr_globs_and_exclusion_precedence(self):
        scope = Scope(['192.0.2.0/24', '*.example.test'], ['192.0.2.66', 'restricted.example.test'])
        self.assertTrue(scope.decision('192.0.2.10')[0])
        self.assertFalse(scope.decision('192.0.2.66')[0])
        self.assertTrue(scope.decision('ws01.example.test', ['192.0.2.10'])[0])
        self.assertFalse(scope.decision('ws01.example.test', ['192.0.2.66'])[0])
        self.assertFalse(scope.decision('restricted.example.test')[0])
        self.assertFalse(Scope(['192.0.2.0/24']).decision('mixed.example.test', ['192.0.2.10', '198.51.100.1'])[0])

    def test_integrity_check_detects_same_size_changes_without_rebaselining(self):
        with tempfile.TemporaryDirectory() as temp:
            file=Path(temp)/'evidence.log';file.write_bytes(b'good')
            inventory=[{'path':'evidence.log','bytes':4,'sha256':hashlib.sha256(b'good').hexdigest()}]
            self.assertTrue(verify_evidence(temp,inventory)['passed'])
            file.write_bytes(b'evil')
            result=verify_evidence(temp,inventory)
            self.assertFalse(result['passed'])
            self.assertEqual(result['files'][0]['status'],'hash-changed')
            self.assertEqual(inventory[0]['sha256'],hashlib.sha256(b'good').hexdigest())


if __name__ == '__main__':
    unittest.main()
