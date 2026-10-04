"""Bounded, offline evidence inspection. Never executes or extracts archive files."""
from __future__ import annotations
import base64
import io
from pathlib import Path
import re
import zipfile
import xml.etree.ElementTree as ET

MAX_BYTES = 2 * 1024 * 1024
MAX_MEMBERS = 64
TEXT_SUFFIXES = {'.txt', '.xml', '.json', '.yaml', '.yml', '.ini', '.config', '.conf', '.ps1', '.vbs', '.csv', '.log', '.bak', '.reg', '.pem'}


def inspect_artifact(path, max_bytes=MAX_BYTES):
    path = Path(path)
    result = {'format': 'unknown', 'status': 'unsupported', 'members': [], 'sections': [], 'warnings': []}
    budget = [max_bytes]
    if path.stat().st_size > max_bytes:
        result['status'] = 'size-limited'
        return result
    data = path.read_bytes()

    def text_section(source, raw):
        text = raw.decode('utf-16' if raw.startswith((b'\xff\xfe', b'\xfe\xff')) else 'utf-8-sig', errors='replace')
        result['sections'].append({'source': source, 'text': text})
        # Decode only small, standalone base64 text. Original evidence remains intact.
        if len(text.strip()) <= 4096 and re.fullmatch(r'[A-Za-z0-9+/]+={0,2}', text.strip()) and len(text.strip()) >= 16:
            try:
                decoded = base64.b64decode(text.strip(), validate=True)
                if decoded and all(c in b'\t\r\n' or 32 <= c < 127 for c in decoded):
                    result['sections'].append({'source': source + ':base64-decoded', 'text': decoded.decode('ascii')})
            except (ValueError, base64.binascii.Error):
                pass

    def archive(raw, source, depth=0):
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            members = z.infolist()
            if source == path.name:
                names = {m.filename for m in members}
                result['format'] = 'xlsx' if 'xl/workbook.xml' in names or 'xl/sharedStrings.xml' in names else 'docx' if 'word/document.xml' in names else 'zip'
                result['status'] = 'inspected'
            for member in members:
                if len(result['members']) >= MAX_MEMBERS:
                    result['status'] = 'partial'; result['warnings'].append('archive member limit'); break
                name = member.filename
                item = {'name': source + '!' + name, 'bytes': member.file_size, 'status': 'metadata-only'}
                result['members'].append(item)
                if member.is_dir(): continue
                if name.startswith(('/', '\\')) or '..' in name.replace('\\', '/').split('/'):
                    item['status'] = 'unsafe-name'; result['status'] = 'partial'; continue
                if member.flag_bits & 1:
                    item['status'] = 'encrypted'; result['status'] = 'partial'; continue
                if member.file_size > budget[0] or member.file_size > max(1, member.compress_size) * 100:
                    item['status'] = 'size-limited'; result['status'] = 'partial'; continue
                suffix = Path(name).suffix.lower()
                if suffix not in TEXT_SUFFIXES | {'.zip', '.xlsx', '.docx'}: continue
                with z.open(member) as f: body = f.read(min(budget[0], member.file_size) + 1)
                if len(body) > budget[0] or len(body) > member.file_size:
                    item['status'] = 'size-limited'; result['status'] = 'partial'; continue
                budget[0] -= len(body)
                item['status'] = 'inspected'
                if suffix in {'.zip', '.xlsx', '.docx'}:
                    if depth >= 1:
                        item['status'] = 'depth-limited'; result['status'] = 'partial'
                    else: archive(body, item['name'], depth + 1)
                elif suffix == '.xml':
                    try:
                        if b'<!DOCTYPE' in body.upper() or b'<!ENTITY' in body.upper(): raise ValueError('XML declarations rejected')
                        root = ET.fromstring(body)
                        values = list(root.itertext())
                        attrs = [f'{k}={v}' for node in root.iter() for k,v in node.attrib.items()]
                        result['sections'].append({'source': item['name'], 'text': '\n'.join(values + attrs)})
                    except (ET.ParseError, ValueError):
                        item['status'] = 'malformed-xml'; result['status'] = 'partial'
                else: text_section(item['name'], body)

    try:
        suffix = path.suffix.lower()
        if data.startswith(b'PK\x03\x04') or zipfile.is_zipfile(io.BytesIO(data)):
            archive(data, path.name)
        elif data.startswith(b'\x03\xd9\xa2\x9ag\xfbK\xb5') or suffix in {'.kdbx', '.psafe3'} or data.startswith(b'PWS3'):
            result.update(format='password-database', status='encrypted')
        elif suffix in {'.pfx', '.p12'}:
            result.update(format='certificate-container', status='encrypted-or-unsupported')
            try:
                from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
                key, cert, others = load_key_and_certificates(data, None)
                result['status'] = 'metadata-inspected'
                result['private_key_present'] = key is not None
                result['certificate_count'] = int(cert is not None) + len(others or [])
                result['certificates'] = [{'subject': c.subject.rfc4514_string(), 'issuer': c.issuer.rfc4514_string(),
                    'expires': (c.not_valid_after_utc if hasattr(c, 'not_valid_after_utc') else c.not_valid_after).isoformat()}
                    for c in ([cert] if cert is not None else []) + list(others or [])]
            except ImportError: result['warnings'].append('optional cryptography parser unavailable')
            except ValueError: result['warnings'].append('container encrypted or malformed; no passwords attempted')
        elif data.startswith(b'%PDF'):
            result.update(format='pdf', status='partial')
            metadata = re.findall(rb'/(?:Author|Title|Creator|Subject)\s*\(([^)]{0,1024})\)', data)
            if metadata: text_section('pdf-metadata', b'\n'.join(metadata))
            result['warnings'].append('PDF text and compressed metadata require external document review')
        elif data.startswith(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'):
            result.update(format='ole-container', status='encrypted-or-unsupported')
        elif data.startswith(b'MZ'):
            result.update(format='windows-executable', status='external-analysis-required')
        elif suffix in TEXT_SUFFIXES or (b'\0' not in data[:4096] and data[:4096].decode('utf-8', errors='replace').count('\ufffd') < 4) or data.startswith((b'\xff\xfe', b'\xfe\xff')):
            result.update(format='text', status='inspected'); text_section(path.name, data)
    except (OSError, ValueError, RuntimeError, zipfile.BadZipFile, NotImplementedError) as exc:
        result['status'] = 'malformed-or-unsupported'; result['warnings'].append(type(exc).__name__)
    return result
