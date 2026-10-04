import base64
import io
from pathlib import Path
import tempfile
import unittest
import zipfile

from nxc_artifacts import inspect_artifact


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def inspect(self, name, body, **limits):
        path = self.root / name
        path.write_bytes(body)
        return inspect_artifact(path, **limits)

    def archive(self, files):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as archive:
            for name, body in files.items(): archive.writestr(name, body)
        return buffer.getvalue()

    def test_xlsx_and_docx_preserve_member_provenance(self):
        for name, member in [('accounts.xlsx', 'xl/sharedStrings.xml'), ('notes.docx', 'word/document.xml')]:
            result = self.inspect(name, self.archive({member:'<root><t>password: fixture</t></root>'}))
            self.assertEqual(result['format'], Path(name).suffix[1:])
            self.assertIn(member, result['sections'][0]['source'])
            self.assertIn('password: fixture', result['sections'][0]['text'])

    def test_base64_and_utf16_text(self):
        for body in [base64.b64encode(b'password: fixture-only'), 'password: fixture-only'.encode('utf-16')]:
            result = self.inspect('note.txt', body)
            self.assertTrue(any('password: fixture-only' in s['text'] for s in result['sections']))

    def test_archive_never_extracts_unsafe_members(self):
        result = self.inspect('sample.zip', self.archive({'../escape.txt':'password: bad', 'safe.txt':'password: okay'}))
        self.assertEqual(result['members'][0]['status'], 'unsafe-name')
        self.assertEqual(len(result['sections']), 1)
        self.assertEqual(list(self.root.iterdir()), [self.root / 'sample.zip'])

    def test_archive_expansion_and_depth_limits(self):
        result = self.inspect('big.zip', self.archive({'bomb.txt':'A' * 100000}))
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['members'][0]['status'], 'size-limited')
        nested = self.archive({'inside.zip':self.archive({'leaf.zip':self.archive({'leaf.txt':'password: fixture'})})})
        result = self.inspect('nested.zip', nested)
        self.assertTrue(any(m['status'] == 'depth-limited' for m in result['members']))

    def test_xml_entity_declarations_are_not_interpreted(self):
        result = self.inspect('sample.zip', self.archive({'unsafe.xml':'<!DOCTYPE r [<!ENTITY s "password: fixture">]><r>&s;</r>'}))
        self.assertEqual(result['status'], 'partial')
        self.assertFalse(result['sections'])

    def test_encrypted_and_partial_formats_are_explicit(self):
        database = self.inspect('vault.kdbx', b'\x03\xd9\xa2\x9ag\xfbK\xb5')
        self.assertEqual(database['status'], 'encrypted')
        pdf = self.inspect('note.pdf', b'%PDF-1.4 /Author (fixture)')
        self.assertEqual(pdf['status'], 'partial')
        self.assertTrue(pdf['warnings'])
        cert = self.inspect('key.pfx', b'not-a-certificate')
        self.assertEqual(cert['status'], 'encrypted-or-unsupported')

    def test_source_size_limit_prevents_inspection(self):
        result = self.inspect('large.txt', b'password: fixture', max_bytes=4)
        self.assertEqual(result['status'], 'size-limited')
        self.assertFalse(result['sections'])
