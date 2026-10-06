"""Tests for the local MIME parser. All samples are generated in code;
everything runs locally in temp dirs / memory. No network, no real mailbox."""

from __future__ import annotations

import base64
import tempfile
import unittest
from pathlib import Path

from mime_parser import (
    LimitExceededError,
    Limits,
    MimeParser,
    TransferEncodingError,
    decode_rfc2047,
    sanitize_filename,
    save_attachments,
)

CRLF = b"\r\n"


def eml(headers: list[tuple[str, str]], body: bytes) -> bytes:
    head = CRLF.join(f"{k}: {v}".encode("utf-8") for k, v in headers)
    return head + CRLF + CRLF + body


def plain_text_eml() -> bytes:
    return eml(
        [
            ("From", "alice@example.com"),
            ("To", "bob@example.com"),
            ("Subject", "Hello there"),
            ("Date", "Wed, 01 Oct 2025 10:00:00 +0800"),
            ("Content-Type", "text/plain; charset=utf-8"),
        ],
        "你好，世界".encode("utf-8"),
    )


def multipart_eml(parts: list[bytes], boundary: str, subtype: str) -> bytes:
    body = b""
    for part in parts:
        body += b"--" + boundary.encode() + CRLF + part + CRLF
    body += b"--" + boundary.encode() + b"--" + CRLF
    return eml(
        [
            ("From", "a@example.com"),
            ("To", "b@example.com"),
            ("Subject", "multipart"),
            ("Content-Type", f'multipart/{subtype}; boundary="{boundary}"'),
        ],
        body,
    )


def part(headers: list[tuple[str, str]], body: bytes) -> bytes:
    return eml(headers, body)


class TestPlainText(unittest.TestCase):
    def test_headers_and_body(self):
        msg = MimeParser().parse_bytes(plain_text_eml())
        self.assertEqual(msg.subject, "Hello there")
        self.assertEqual(msg.from_, "alice@example.com")
        self.assertEqual(msg.to, "bob@example.com")
        self.assertEqual(msg.date, "Wed, 01 Oct 2025 10:00:00 +0800")
        self.assertEqual(msg.text_body, "你好，世界")
        self.assertIsNone(msg.html_body)
        self.assertEqual(msg.attachments, [])


class TestMultipart(unittest.TestCase):
    def test_alternative_text_and_html(self):
        eml_bytes = multipart_eml(
            [
                part([("Content-Type", "text/plain; charset=utf-8")], b"plain body"),
                part([("Content-Type", "text/html; charset=utf-8")], b"<p>html</p>"),
            ],
            "alt-boundary",
            "alternative",
        )
        msg = MimeParser().parse_bytes(eml_bytes)
        self.assertEqual(msg.text_body, "plain body")
        self.assertEqual(msg.html_body, "<p>html</p>")
        self.assertEqual(msg.attachments, [])

    def test_mixed_with_attachment(self):
        payload = b"\x89PNG\r\n\x1a\nfake-image-bytes"
        eml_bytes = multipart_eml(
            [
                part([("Content-Type", "text/plain; charset=utf-8")], b"see attached"),
                part(
                    [
                        ("Content-Type", "image/png"),
                        ("Content-Transfer-Encoding", "base64"),
                        ("Content-Disposition", 'attachment; filename="pic.png"'),
                    ],
                    base64.b64encode(payload),
                ),
            ],
            "mix-boundary",
            "mixed",
        )
        msg = MimeParser().parse_bytes(eml_bytes)
        self.assertEqual(msg.text_body, "see attached")
        self.assertEqual(len(msg.attachments), 1)
        att = msg.attachments[0]
        self.assertEqual(att.filename, "pic.png")
        self.assertEqual(att.content_type, "image/png")
        self.assertEqual(att.data, payload)

    def test_nested_rfc822_message(self):
        inner = plain_text_eml()
        eml_bytes = multipart_eml(
            [
                part([("Content-Type", "text/plain")], b"outer"),
                part([("Content-Type", "message/rfc822")], inner),
            ],
            "nest-boundary",
            "mixed",
        )
        msg = MimeParser().parse_bytes(eml_bytes)
        self.assertEqual(msg.text_body, "outer")


class TestEncodedWordsAndFolding(unittest.TestCase):
    def test_utf8_base64_encoded_word(self):
        raw = "=?UTF-8?B?" + base64.b64encode("中文标题".encode()).decode() + "?="
        self.assertEqual(decode_rfc2047(raw), "中文标题")

    def test_utf8_q_encoded_word(self):
        raw = "=?UTF-8?Q?hello_=E4=B8=96=E7=95=8C?="
        self.assertEqual(decode_rfc2047(raw), "hello 世界")

    def test_gbk_encoded_word(self):
        raw = "=?GBK?B?" + base64.b64encode("中文".encode("gbk")).decode() + "?="
        self.assertEqual(decode_rfc2047(raw), "中文")

    def test_adjacent_words_merge(self):
        enc = lambda s: "=?UTF-8?B?" + base64.b64encode(s.encode()).decode() + "?="
        self.assertEqual(decode_rfc2047(enc("你好") + " " + enc("世界")), "你好世界")

    def test_unknown_charset_kept_raw(self):
        raw = "=?X-UNKNOWN?B?AAAA?="
        self.assertEqual(decode_rfc2047(raw), raw)

    def test_folded_subject_header(self):
        eml_bytes = (
            b"From: a@example.com\r\n"
            b"Subject: this is a very long\r\n"
            b"\tfolded subject line\r\n"
            b"Content-Type: text/plain\r\n"
            b"\r\n"
            b"body"
        )
        msg = MimeParser().parse_bytes(eml_bytes)
        self.assertEqual(msg.subject, "this is a very long folded subject line")

    def test_encoded_word_in_eml_subject(self):
        subject = "=?UTF-8?B?" + base64.b64encode("账单已生成".encode()).decode() + "?="
        msg = MimeParser().parse_bytes(
            eml([("Subject", subject), ("Content-Type", "text/plain")], b"x")
        )
        self.assertEqual(msg.subject, "账单已生成")


class TestTransferEncoding(unittest.TestCase):
    def test_quoted_printable_body(self):
        eml_bytes = eml(
            [
                ("Content-Type", "text/plain; charset=utf-8"),
                ("Content-Transfer-Encoding", "quoted-printable"),
            ],
            "hello=20=E4=B8=96=E7=95=8C".encode(),
        )
        msg = MimeParser().parse_bytes(eml_bytes)
        self.assertEqual(msg.text_body, "hello 世界")

    def test_base64_body(self):
        eml_bytes = eml(
            [
                ("Content-Type", "text/plain; charset=utf-8"),
                ("Content-Transfer-Encoding", "base64"),
            ],
            base64.b64encode("hello 世界".encode()),
        )
        msg = MimeParser().parse_bytes(eml_bytes)
        self.assertEqual(msg.text_body, "hello 世界")

    def test_corrupt_base64_illegal_chars_strict(self):
        eml_bytes = eml(
            [
                ("Content-Type", "application/octet-stream"),
                ("Content-Transfer-Encoding", "base64"),
                ("Content-Disposition", 'attachment; filename="x.bin"'),
            ],
            b"QUJD!!!RA==",
        )
        with self.assertRaises(TransferEncodingError):
            MimeParser(strict=True).parse_bytes(eml_bytes)

    def test_truncated_base64_strict(self):
        eml_bytes = eml(
            [
                ("Content-Type", "application/octet-stream"),
                ("Content-Transfer-Encoding", "base64"),
                ("Content-Disposition", 'attachment; filename="x.bin"'),
            ],
            b"Q",  # truncated: not a valid length
        )
        with self.assertRaises(TransferEncodingError):
            MimeParser(strict=True).parse_bytes(eml_bytes)

    def test_corrupt_base64_lenient_warns(self):
        eml_bytes = eml(
            [
                ("Content-Type", "application/octet-stream"),
                ("Content-Transfer-Encoding", "base64"),
                ("Content-Disposition", 'attachment; filename="x.bin"'),
            ],
            b"QUJD!!!RA==",
        )
        msg = MimeParser().parse_bytes(eml_bytes)
        self.assertTrue(msg.warnings)
        self.assertEqual(msg.attachments[0].data, b"QUJD!!!RA==")

    def test_corrupt_quoted_printable_strict(self):
        eml_bytes = eml(
            [
                ("Content-Type", "text/plain"),
                ("Content-Transfer-Encoding", "quoted-printable"),
            ],
            b"bad escape =ZZ here",
        )
        with self.assertRaises(TransferEncodingError):
            MimeParser(strict=True).parse_bytes(eml_bytes)

    def test_dangling_qp_equals_strict(self):
        eml_bytes = eml(
            [
                ("Content-Type", "text/plain"),
                ("Content-Transfer-Encoding", "quoted-printable"),
            ],
            b"truncated line ends with =",
        )
        with self.assertRaises(TransferEncodingError):
            MimeParser(strict=True).parse_bytes(eml_bytes)


class TestFilenameSafety(unittest.TestCase):
    def test_sanitize_strips_traversal(self):
        self.assertEqual(sanitize_filename("../../etc/passwd"), "passwd")
        self.assertEqual(sanitize_filename("..\\..\\win\\system.ini"), "system.ini")
        self.assertEqual(sanitize_filename("/abs/path/file.txt"), "file.txt")
        self.assertEqual(sanitize_filename("C:\\temp\\evil.exe"), "evil.exe")
        self.assertEqual(sanitize_filename(".."), "attachment")
        self.assertEqual(sanitize_filename(""), "attachment")

    def test_traversal_filename_in_eml(self):
        eml_bytes = multipart_eml(
            [
                part(
                    [
                        ("Content-Type", "application/octet-stream"),
                        (
                            "Content-Disposition",
                            'attachment; filename="../../etc/cron.d/evil"',
                        ),
                    ],
                    b"payload",
                )
            ],
            "trav-boundary",
            "mixed",
        )
        msg = MimeParser().parse_bytes(eml_bytes)
        self.assertEqual(msg.attachments[0].filename, "evil")

    def test_save_attachments_stays_in_dir(self):
        eml_bytes = multipart_eml(
            [
                part(
                    [
                        ("Content-Type", "application/octet-stream"),
                        (
                            "Content-Disposition",
                            'attachment; filename="../../../tmp/escape.txt"',
                        ),
                    ],
                    b"data",
                ),
                part(
                    [
                        ("Content-Type", "application/octet-stream"),
                        ("Content-Disposition", 'attachment; filename="ok.txt"'),
                    ],
                    b"ok",
                ),
            ],
            "save-boundary",
            "mixed",
        )
        msg = MimeParser().parse_bytes(eml_bytes)
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            paths = save_attachments(msg, out)
            self.assertEqual(len(paths), 2)
            for p in paths:
                self.assertTrue(str(p.resolve()).startswith(str(out.resolve())))
            self.assertEqual((out / "escape.txt").read_bytes(), b"data")
            self.assertEqual((out / "ok.txt").read_bytes(), b"ok")


class TestLimits(unittest.TestCase):
    def _nested(self, depth: int) -> bytes:
        inner = part([("Content-Type", "text/plain")], b"deep")
        for i in range(depth):
            inner = part(
                [
                    (
                        "Content-Type",
                        f'multipart/mixed; boundary="nest-{i}"',
                    )
                ],
                b"--nest-%d\r\n" % i
                + inner
                + b"\r\n--nest-%d--\r\n" % i,
            )
        return inner

    def test_max_depth_exceeded(self):
        eml_bytes = self._nested(10)
        with self.assertRaises(LimitExceededError):
            MimeParser(Limits(max_depth=5)).parse_bytes(eml_bytes)

    def test_within_depth_ok(self):
        eml_bytes = self._nested(3)
        msg = MimeParser(Limits(max_depth=10)).parse_bytes(eml_bytes)
        self.assertEqual(msg.text_body, "deep")

    def test_max_attachments(self):
        parts = [
            part(
                [
                    ("Content-Type", "application/octet-stream"),
                    ("Content-Disposition", f'attachment; filename="f{i}.bin"'),
                ],
                b"x",
            )
            for i in range(5)
        ]
        eml_bytes = multipart_eml(parts, "many-boundary", "mixed")
        with self.assertRaises(LimitExceededError):
            MimeParser(Limits(max_attachments=3)).parse_bytes(eml_bytes)

    def test_max_total_bytes(self):
        big = base64.b64encode(b"A" * 4096)
        eml_bytes = eml(
            [
                ("Content-Type", "application/octet-stream"),
                ("Content-Transfer-Encoding", "base64"),
                ("Content-Disposition", 'attachment; filename="big.bin"'),
            ],
            big,
        )
        with self.assertRaises(LimitExceededError):
            MimeParser(Limits(max_total_bytes=1024)).parse_bytes(eml_bytes)

    def test_max_header_bytes(self):
        eml_bytes = eml(
            [("X-Long", "v" * 5000), ("Content-Type", "text/plain")], b"body"
        )
        with self.assertRaises(LimitExceededError):
            MimeParser(Limits(max_header_bytes=1024)).parse_bytes(eml_bytes)


class TestParseFile(unittest.TestCase):
    def test_parse_local_eml_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.eml"
            path.write_bytes(plain_text_eml())
            msg = MimeParser().parse_file(path)
            self.assertEqual(msg.subject, "Hello there")
            self.assertEqual(msg.text_body, "你好，世界")


if __name__ == "__main__":
    unittest.main()
