from datetime import datetime, timezone
import gzip
import hashlib
import io
import json
import tarfile
import unittest

from hosted.lightsail.export_data import TABLES
from hosted.lightsail.import_data import COPY_HEADER, parse_archive


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.schema = "a" * 64
        self.copy = COPY_HEADER + b"\0" * 8 + b"\xff\xff"
        self.manifest = {"format": "verify-copy-v1", "purpose": "rehearsal",
                         "capturedAtUtc": datetime.now(timezone.utc).isoformat(),
                         "schemaSha256": self.schema,
                         "tables": {name: {"rows": 0, "columns": [["id", "text"]],
                             "bytes": len(self.copy), "sha256": hashlib.sha256(self.copy).hexdigest()}
                             for name in TABLES}}

    def archive(self, extra=None, omit=None, data=None):
        files = {name + ".copy": self.copy for name in TABLES}
        if data:
            files.update(data)
        files["manifest.json"] = json.dumps(self.manifest).encode()
        if omit:
            files.pop(omit)
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w") as archive:
            for name, content in files.items():
                item = tarfile.TarInfo(name)
                item.size = len(content)
                archive.addfile(item, io.BytesIO(content))
            if extra:
                archive.addfile(extra, io.BytesIO(b""))
        packed = gzip.compress(output.getvalue(), mtime=0)
        return packed, hashlib.sha256(packed).hexdigest()

    def parse(self, **kwargs):
        packed, digest = self.archive(**kwargs)
        return parse_archive(packed, digest, self.schema, "rehearsal")

    def test_valid_archive_contains_all_seven_tables(self):
        files, manifest = self.parse()
        self.assertEqual(len(files), 7)
        self.assertEqual(manifest, self.manifest)

    def test_independent_outer_digest_and_schema_are_required(self):
        packed, digest = self.archive()
        for archive_digest, schema_digest in (("0" * 64, self.schema), (digest, "0" * 64)):
            with self.subTest(archive_digest=archive_digest), self.assertRaises(ValueError):
                parse_archive(packed, archive_digest, schema_digest, "rehearsal")

    def test_path_traversal_duplicate_and_symlink_are_rejected(self):
        for name, kind in (("../escape", tarfile.REGTYPE), ("tenant.copy", tarfile.REGTYPE),
                           ("symlink", tarfile.SYMTYPE)):
            member = tarfile.TarInfo(name)
            member.type = kind
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.parse(extra=member)

    def test_copy_tampering_or_missing_table_is_rejected(self):
        with self.assertRaises(ValueError):
            self.parse(data={"event.copy": self.copy + b"tampered"})
        with self.assertRaises(ValueError):
            self.parse(omit="tenant.copy")

    def test_noninteger_counts_and_unknown_tables_are_rejected(self):
        self.manifest["tables"]["tenant"]["rows"] = True
        with self.assertRaises(ValueError):
            self.parse()
        self.manifest["tables"]["tenant"]["rows"] = 0
        self.manifest["tables"]["unknown"] = {}
        with self.assertRaises(ValueError):
            self.parse()

    def test_rehearsal_cannot_be_imported_as_final(self):
        packed, digest = self.archive()
        with self.assertRaises(ValueError):
            parse_archive(packed, digest, self.schema, "final")

    def test_stale_final_and_bad_columns_are_rejected(self):
        self.manifest.update(purpose="final", capturedAtUtc="2000-01-01T00:00:00+00:00")
        packed, digest = self.archive()
        with self.assertRaises(ValueError):
            parse_archive(packed, digest, self.schema, "final")
        self.manifest["purpose"] = "rehearsal"
        self.manifest["tables"]["tenant"]["columns"] = [["id", "text"], ["id", "text"]]
        with self.assertRaises(ValueError):
            self.parse()


if __name__ == "__main__":
    unittest.main()
