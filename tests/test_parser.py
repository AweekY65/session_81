"""Tests for the local MIME parser.

Every .eml sample is generated in code and only ever written to a local
temporary directory. No network, SMTP, IMAP, or external service is used.
"""

import base64
import tempfile
import unittest
from pathlib import Path

from mime_parser import (
    LimitExceededError,
    Limits,
    MimeParser,
    TransferEncodingError,
    sanitize_filename,
    save_attachments,
)

CRLF = "\r\n"


def eml(headers: list[str], body: str | bytes) -> bytes:
    head = CRLF.join(headers) + CRLF + CRLF
    if isinstance(body, str):
        return head.encode("utf-8") + body.encode("utf-8")
    return head.encode("utf-8") + body


def multipart(boundary: str, parts: list[bytes]) -> bytes:
    out = b""
    for part in parts:
        out += f"--{boundary}{CRLF}".encode() + part + CRLF.encode()
    out += f"--{boundary}--{CRLF}".encode()
    return out


class TestPlainText(unittest.TestCase):
    def test_simple_text_message(self):
        raw = eml(
            [
                "From: alice@example.com",
                "To: bob@example.com",
                "Subject: Hello there",
                "Date: Mon, 1 Jan 2024 10:00:00 +0000",
                "Content-Type: text/plain; charset=utf-8",
            ],
            "Hello, Bob!",
        )
        msg = MimeParser().parse_bytes(raw)
        self.assertEqual(msg.from_, "alice@example.com")
        self.assertEqual(msg.to, "bob@example.com")
        self.assertEqual(msg.subject, "Hello there")
        self.assertEqual(msg.date, "Mon, 1 Jan 2024 10:00:00 +0000")
        self.assertEqual(msg.text_body, "Hello, Bob!")
        self.assertEqual(msg.attachments, [])

    def test_quoted_printable_body(self):
        raw = eml(
            [
                "Subject: qp",
                "Content-Type: text/plain; charset=utf-8",
                "Content-Transfer-Encoding: quoted-printable",
            ],
            "caf=C3=A9 au lait" + CRLF + "soft=" + CRLF + "break",
        )
        msg = MimeParser().parse_bytes(raw)
        self.assertIn("café au lait", msg.text_body)
        self.assertIn("softbreak", msg.text_body)

    def test_invalid_quoted_printable_detected(self):
        raw = eml(
            [
                "Content-Type: text/plain",
                "Content-Transfer-Encoding: quoted-printable",
            ],
            "bad escape: =ZZ here",
        )
        msg = MimeParser().parse_bytes(raw)
        self.assertTrue(any("quoted-printable" in w for w in msg.warnings))
        with self.assertRaises(TransferEncodingError):
            MimeParser(strict=True).parse_bytes(raw)


class TestMultipart(unittest.TestCase):
    def test_multipart_alternative(self):
        plain = eml(["Content-Type: text/plain; charset=utf-8"], "plain version")
        html = eml(["Content-Type: text/html; charset=utf-8"], "<p>html version</p>")
        raw = eml(
            ["Subject: alt", 'Content-Type: multipart/alternative; boundary="alt-b"'],
            multipart("alt-b", [plain, html]),
        )
        msg = MimeParser().parse_bytes(raw)
        self.assertEqual(msg.text_body, "plain version")
        self.assertEqual(msg.html_body, "<p>html version</p>")
        self.assertEqual(msg.attachments, [])

    def test_multipart_mixed_with_attachment(self):
        payload = base64.b64encode(b"file-bytes-here").decode()
        text_part = eml(["Content-Type: text/plain; charset=utf-8"], "see attached")
        att_part = eml(
            [
                "Content-Type: application/octet-stream",
                "Content-Transfer-Encoding: base64",
                'Content-Disposition: attachment; filename="report.bin"',
            ],
            payload,
        )
        raw = eml(
            ['Content-Type: multipart/mixed; boundary="mix-b"'],
            multipart("mix-b", [text_part, att_part]),
        )
        msg = MimeParser().parse_bytes(raw)
        self.assertEqual(msg.text_body, "see attached")
        self.assertEqual(len(msg.attachments), 1)
        att = msg.attachments[0]
        self.assertEqual(att.filename, "report.bin")
        self.assertEqual(att.data, b"file-bytes-here")

    def test_nested_mixed_in_alternative(self):
        plain = eml(["Content-Type: text/plain"], "outer plain")
        html = eml(["Content-Type: text/html"], "<b>outer html</b>")
        alt = eml(
            ['Content-Type: multipart/alternative; boundary="inner"'],
            multipart("inner", [plain, html]),
        )
        att = eml(
            [
                "Content-Type: text/plain; name=data.txt",
                'Content-Disposition: attachment; filename="data.txt"',
            ],
            "attachment text",
        )
        raw = eml(
            ['Content-Type: multipart/mixed; boundary="outer"'],
            multipart("outer", [alt, att]),
        )
        msg = MimeParser().parse_bytes(raw)
        self.assertEqual(msg.text_body, "outer plain")
        self.assertEqual(msg.html_body, "<b>outer html</b>")
        self.assertEqual([a.filename for a in msg.attachments], ["data.txt"])
        self.assertEqual(msg.attachments[0].data, b"attachment text")


class TestHeaders(unittest.TestCase):
    def test_encoded_word_utf8_base64(self):
        subject = "=?UTF-8?B?" + base64.b64encode("你好，世界".encode()).decode() + "?="
        msg = MimeParser().parse_bytes(eml([f"Subject: {subject}"], "x"))
        self.assertEqual(msg.subject, "你好，世界")

    def test_encoded_word_utf8_q_and_gbk(self):
        q = "=?UTF-8?Q?h=C3=A9llo?="
        gbk = "=?GBK?B?" + base64.b64encode("中文标题".encode("gbk")).decode() + "?="
        msg = MimeParser().parse_bytes(eml([f"Subject: {q} {gbk}"], "x"))
        self.assertEqual(msg.subject, "héllo中文标题")

    def test_folded_headers(self):
        raw = eml(
            [
                "Subject: this is a very long",
                "\tfolded subject line",
                "To: alice@example.com,",
                " bob@example.com",
                "X-Other: 1",
            ],
            "body",
        )
        msg = MimeParser().parse_bytes(raw)
        self.assertEqual(msg.subject, "this is a very long folded subject line")
        self.assertEqual(msg.to, "alice@example.com, bob@example.com")

    def test_attachment_filename_encoded_word(self):
        att = eml(
            [
                "Content-Type: application/pdf",
                "Content-Disposition: attachment; "
                'filename="=?UTF-8?B?' + base64.b64encode("报告.pdf".encode()).decode() + '?="',
            ],
            "pdfdata",
        )
        raw = eml(['Content-Type: multipart/mixed; boundary="b"'], multipart("b", [att]))
        msg = MimeParser().parse_bytes(raw)
        self.assertEqual(msg.attachments[0].filename, "报告.pdf")


class TestFilenameSafety(unittest.TestCase):
    def test_sanitize_strips_traversal(self):
        self.assertEqual(sanitize_filename("../../etc/passwd"), "passwd")
        self.assertEqual(sanitize_filename("..\\..\\win\\evil.exe"), "evil.exe")
        self.assertEqual(sanitize_filename("/etc/shadow"), "shadow")
        self.assertEqual(sanitize_filename(".."), "attachment-0")
        self.assertEqual(sanitize_filename("", 3), "attachment-3")
        self.assertEqual(sanitize_filename("a<b>:c.txt"), "a_b__c.txt")

    def test_traversal_attachment_stays_in_outdir(self):
        att = eml(
            [
                "Content-Type: application/octet-stream",
                'Content-Disposition: attachment; filename="../../evil.sh"',
            ],
            "malicious",
        )
        raw = eml(['Content-Type: multipart/mixed; boundary="b"'], multipart("b", [att]))
        msg = MimeParser().parse_bytes(raw)
        self.assertEqual(msg.attachments[0].filename, "evil.sh")
        with tempfile.TemporaryDirectory() as tmp:
            outdir = Path(tmp) / "out"
            written = save_attachments(msg, outdir)
            self.assertEqual(len(written), 1)
            self.assertEqual(written[0].parent, outdir.resolve())
            self.assertEqual(written[0].name, "evil.sh")
            self.assertFalse((Path(tmp) / "evil.sh").exists())


class TestCorruptBase64(unittest.TestCase):
    def _mail_with_b64(self, payload: str) -> bytes:
        att = eml(
            [
                "Content-Type: application/octet-stream",
                "Content-Transfer-Encoding: base64",
                'Content-Disposition: attachment; filename="x.bin"',
            ],
            payload,
        )
        return eml(['Content-Type: multipart/mixed; boundary="b"'], multipart("b", [att]))

    def test_illegal_characters(self):
        raw = self._mail_with_b64("SGVsbG8###=")
        msg = MimeParser().parse_bytes(raw)
        self.assertTrue(any("base64" in w for w in msg.warnings))
        with self.assertRaises(TransferEncodingError):
            MimeParser(strict=True).parse_bytes(raw)

    def test_truncated_payload(self):
        raw = self._mail_with_b64("SGVsbG8")  # length not a multiple of 4
        msg = MimeParser().parse_bytes(raw)
        self.assertTrue(any("truncated" in w for w in msg.warnings))
        with self.assertRaises(TransferEncodingError):
            MimeParser(strict=True).parse_bytes(raw)

    def test_valid_base64_with_whitespace(self):
        raw = self._mail_with_b64("SGVs\r\nbG8s\r\nIHdv\r\ncmxk\r\n")
        msg = MimeParser().parse_bytes(raw)
        self.assertEqual(msg.warnings, [])
        self.assertEqual(msg.attachments[0].data, b"Hello, world")


class TestLimits(unittest.TestCase):
    def test_nesting_depth_limit(self):
        depth = 30
        inner = eml(["Content-Type: text/plain"], "deep")
        for i in range(depth):
            inner = eml(
                [f'Content-Type: multipart/mixed; boundary="d{i}"'],
                multipart(f"d{i}", [inner]),
            )
        with self.assertRaises(LimitExceededError):
            MimeParser().parse_bytes(inner)
        # With a higher limit the same message parses fine.
        msg = MimeParser(Limits(max_depth=64)).parse_bytes(inner)
        self.assertEqual(msg.text_body, "deep")

    def test_attachment_count_limit(self):
        parts = [
            eml(
                [
                    "Content-Type: application/octet-stream",
                    f'Content-Disposition: attachment; filename="f{i}.bin"',
                ],
                "x",
            )
            for i in range(5)
        ]
        raw = eml(['Content-Type: multipart/mixed; boundary="b"'], multipart("b", parts))
        with self.assertRaises(LimitExceededError):
            MimeParser(Limits(max_attachments=3)).parse_bytes(raw)
        msg = MimeParser(Limits(max_attachments=5)).parse_bytes(raw)
        self.assertEqual(len(msg.attachments), 5)

    def test_total_size_limit(self):
        big = base64.b64encode(b"A" * 4096).decode()
        att = eml(
            [
                "Content-Type: application/octet-stream",
                "Content-Transfer-Encoding: base64",
                'Content-Disposition: attachment; filename="big.bin"',
            ],
            big,
        )
        raw = eml(['Content-Type: multipart/mixed; boundary="b"'], multipart("b", [att]))
        with self.assertRaises(LimitExceededError):
            MimeParser(Limits(max_total_bytes=1024)).parse_bytes(raw)


class TestLocalFileParsing(unittest.TestCase):
    def test_parse_eml_file_and_extract(self):
        payload = base64.b64encode("附件内容".encode()).decode()
        att = eml(
            [
                "Content-Type: text/plain",
                "Content-Transfer-Encoding: base64",
                'Content-Disposition: attachment; filename="notes.txt"',
            ],
            payload,
        )
        body = eml(["Content-Type: text/plain; charset=utf-8"], "正文")
        raw = eml(
            [
                "From: a@b.c",
                "Subject: local file test",
                'Content-Type: multipart/mixed; boundary="b"',
            ],
            multipart("b", [body, att]),
        )
        with tempfile.TemporaryDirectory() as tmp:
            eml_path = Path(tmp) / "sample.eml"
            eml_path.write_bytes(raw)
            msg = MimeParser().parse_file(eml_path)
            self.assertEqual(msg.subject, "local file test")
            self.assertEqual(msg.text_body, "正文")
            written = save_attachments(msg, Path(tmp) / "attachments")
            self.assertEqual(written[0].read_bytes(), "附件内容".encode())


if __name__ == "__main__":
    unittest.main()
