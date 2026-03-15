#!/usr/bin/env python3
"""
Spain Mobile ID (DNI / MiDNI) QR Decoder

Decodes QR payloads from Spain's MiDNI app, which encode identity data
as ICAO 9303-13 Visible Digital Seals (VDS) signed with ECDSA.

Usage:
    python SpainMobileIDDecoder.py --file payload.bin
    python SpainMobileIDDecoder.py --stdin < payload.bin
    python SpainMobileIDDecoder.py --stdin --open-image < payload.bin
    python SpainMobileIDDecoder.py --json 'dc037581...'
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)

MAGIC_CONSTANT = 0xDC
SIGNATURE_TAG = 0xFF
QR_BYTE_MODE = 0x4


# ---------------------------------------------------------------------------
# C40 encoding
# ---------------------------------------------------------------------------

C40_CHARSET: dict[int, str] = {3: ' '}
for _i in range(10):
    C40_CHARSET[4 + _i] = chr(ord('0') + _i)
for _i in range(26):
    C40_CHARSET[14 + _i] = chr(ord('A') + _i)


def decode_c40(data: bytes) -> str:
    """Decode C40-encoded bytes (ICAO 9303-13 / Data Matrix C40)."""
    result: list[str] = []
    i = 0
    while i + 1 < len(data):
        b1, b2 = data[i], data[i + 1]
        i += 2
        if b1 == 0xFE:
            result.append(chr(b2))
            continue
        value = b1 * 256 + b2 - 1
        for c in (value // 1600, (value % 1600) // 40, value % 40):
            if c in C40_CHARSET:
                result.append(C40_CHARSET[c])
    return ''.join(result)


# ---------------------------------------------------------------------------
# BER-TLV length
# ---------------------------------------------------------------------------

def read_ber_length(data: bytes, offset: int) -> tuple[int, int]:
    """Read a BER-TLV length. Returns (length_value, bytes_consumed)."""
    first = data[offset]
    if first < 0x80:
        return first, 1
    num_bytes = first & 0x7F
    return int.from_bytes(data[offset + 1:offset + 1 + num_bytes], 'big'), 1 + num_bytes


def ber_length_size(length: int) -> int:
    """Number of bytes needed to encode a BER length value."""
    if length < 0x80:
        return 1
    if length <= 0xFF:
        return 2
    if length <= 0xFFFF:
        return 3
    return 4


# ---------------------------------------------------------------------------
# QR raw data unwrapping
# ---------------------------------------------------------------------------

def _shift_bits_left(data: bytes, n: int) -> bytes:
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = (data[i] << n) & 0xFF
        if i + 1 < len(data):
            result[i] |= data[i + 1] >> (8 - n)
    return bytes(result)


def unwrap_qr_raw_data(raw: bytes) -> bytes:
    """Strip QR byte-mode header (4-bit mode + 8/16-bit count) if present."""
    if not raw or raw[0] == MAGIC_CONSTANT:
        return raw
    if (raw[0] >> 4) != QR_BYTE_MODE:
        return raw
    for count_bits in (16, 8):
        header_bits = 4 + count_bits
        skip_bytes = header_bits // 8
        shift = header_bits % 8
        if skip_bytes >= len(raw):
            continue
        payload = _shift_bits_left(raw[skip_bytes:], shift) if shift else raw[skip_bytes:]
        if payload and payload[0] == MAGIC_CONSTANT:
            if count_bits == 16:
                count = ((raw[0] & 0x0F) << 12) | (raw[1] << 4) | (raw[2] >> 4)
            else:
                count = ((raw[0] & 0x0F) << 4) | (raw[1] >> 4)
            return payload[:count]
    return raw


# ---------------------------------------------------------------------------
# VDS header date
# ---------------------------------------------------------------------------

def decode_header_date(data: bytes) -> str:
    """Decode a 3-byte VDS header date (big-endian MMDDYYYY as integer)."""
    value = int.from_bytes(data, 'big')
    digits = f"{value:08d}"
    month, day, year = int(digits[0:2]), int(digits[2:4]), int(digits[4:8])
    return f"{day:02d}-{month:02d}-{year:04d}"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class VDSHeader:
    version: int
    issuing_country: str
    signer_id: str
    certificate_reference: str
    document_issue_date: str
    signature_creation_date: str
    document_feature_ref: int
    document_type_category: int


@dataclass
class VDSTlv:
    tag: int
    value: bytes

    @property
    def tag_hex(self) -> str:
        return f"0x{self.tag:02X}"

    @property
    def is_signature(self) -> bool:
        return self.tag == SIGNATURE_TAG

    def value_as_text(self) -> str | None:
        try:
            return self.value.decode('utf-8')
        except (UnicodeDecodeError, ValueError):
            return None

    def value_as_hex(self) -> str:
        return self.value.hex().upper()


@dataclass
class VDSSeal:
    header: VDSHeader
    tlvs: list[VDSTlv] = field(default_factory=list)
    signature: VDSTlv | None = None
    signed_data: bytes = b''

    @property
    def message_tlvs(self) -> list[VDSTlv]:
        return [t for t in self.tlvs if not t.is_signature]

    def get_tlv(self, tag: int) -> VDSTlv | None:
        for t in self.tlvs:
            if t.tag == tag:
                return t
        return None

    def get_value(self, tag: int) -> bytes | None:
        tlv = self.get_tlv(tag)
        return tlv.value if tlv else None

    def get_text(self, tag: int) -> str | None:
        tlv = self.get_tlv(tag)
        return tlv.value_as_text() if tlv else None


# ---------------------------------------------------------------------------
# Raw parsing
# ---------------------------------------------------------------------------

def parse_header(data: bytes) -> tuple[VDSHeader, int]:
    offset = 0

    magic = data[offset]
    if magic != MAGIC_CONSTANT:
        raise ValueError(f"Invalid magic constant: 0x{magic:02X} (expected 0xDC)")
    offset += 1

    version = data[offset]
    offset += 1

    issuing_country = decode_c40(data[offset:offset + 2])
    offset += 2

    signer_prefix = decode_c40(data[offset:offset + 4])
    offset += 4
    signer_id = signer_prefix[0:4]
    cert_ref_char_count = int(signer_prefix[4:6], 16)
    cert_ref_c40_bytes = ((cert_ref_char_count + 2) // 3) * 2

    certificate_reference = decode_c40(data[offset:offset + cert_ref_c40_bytes])
    offset += cert_ref_c40_bytes

    document_issue_date = decode_header_date(data[offset:offset + 3])
    offset += 3
    signature_creation_date = decode_header_date(data[offset:offset + 3])
    offset += 3

    document_feature_ref = data[offset]
    offset += 1
    document_type_category = data[offset]
    offset += 1

    return VDSHeader(
        version=version,
        issuing_country=issuing_country,
        signer_id=signer_id,
        certificate_reference=certificate_reference,
        document_issue_date=document_issue_date,
        signature_creation_date=signature_creation_date,
        document_feature_ref=document_feature_ref,
        document_type_category=document_type_category,
    ), offset


def parse_tlvs(data: bytes, offset: int) -> list[VDSTlv]:
    tlvs: list[VDSTlv] = []
    while offset < len(data):
        tag = data[offset]
        offset += 1
        length, consumed = read_ber_length(data, offset)
        offset += consumed
        value = data[offset:offset + length]
        offset += length
        tlvs.append(VDSTlv(tag=tag, value=value))
        if tag == SIGNATURE_TAG:
            break
    return tlvs


def parse_seal(data: bytes) -> VDSSeal:
    """Parse raw bytes into a VDSSeal (with QR unwrapping)."""
    data = unwrap_qr_raw_data(data)
    header, body_offset = parse_header(data)
    tlvs = parse_tlvs(data, body_offset)

    signature = None
    signed_data_end = body_offset
    for tlv in tlvs:
        if tlv.is_signature:
            signature = tlv
            break
        signed_data_end += 1 + ber_length_size(len(tlv.value)) + len(tlv.value)

    return VDSSeal(
        header=header,
        tlvs=tlvs,
        signature=signature,
        signed_data=data[:signed_data_end],
    )


# ---------------------------------------------------------------------------
# VDSDecoder (base)
# ---------------------------------------------------------------------------

HEADER_LABELS: dict[str, str] = {
    "version": "Version",
    "issuing_country": "Issuing country",
    "signer_id": "Signer ID",
    "certificate_reference": "Certificate reference",
    "document_issue_date": "Document issue date",
    "signature_creation_date": "Signature creation date",
    "document_feature_ref": "Document feature ref",
    "document_type_category": "Document type category",
    "verification_type": "Verification type",
    "document_type": "Document type",
}


class VDSDecoder:
    """Generic ICAO 9303-13 VDS decoder. Subclass to add profile-specific
    tag definitions, header enrichment, and field interpretation."""

    name = "ICAO 9303-13 VDS"
    tag_definitions: dict[int, str] = {}
    field_labels: dict[str, str] = {}
    image_tags: set[int] = set()
    display_order: list[str] = []

    def parse(self, data: bytes) -> VDSSeal:
        return parse_seal(data)

    # -- Header --

    def interpret_header(self, header: VDSHeader) -> dict[str, Any]:
        return {
            "version": header.version,
            "issuing_country": header.issuing_country,
            "signer_id": header.signer_id,
            "certificate_reference": header.certificate_reference,
            "document_issue_date": header.document_issue_date,
            "signature_creation_date": header.signature_creation_date,
            "document_feature_ref": header.document_feature_ref,
            "document_type_category": header.document_type_category,
        }

    # -- TLVs --

    def _tag_key(self, tag: int) -> str:
        return self.tag_definitions.get(tag, f"0x{tag:02X}")

    def interpret_tlv(self, tlv: VDSTlv) -> tuple[str, Any]:
        key = self._tag_key(tlv.tag)
        text = tlv.value_as_text()
        if text is not None:
            return key, text
        if len(tlv.value) <= 64:
            return key, tlv.value_as_hex()
        return key, f"[{len(tlv.value)} bytes]"

    # -- Full interpretation --

    def interpret(self, seal: VDSSeal) -> dict[str, Any]:
        fields: dict[str, Any] = {}
        image_data: bytes | None = None

        for tlv in seal.message_tlvs:
            key, value = self.interpret_tlv(tlv)
            fields[key] = value
            if tlv.tag in self.image_tags:
                image_data = tlv.value

        if seal.signature:
            fields["signature"] = seal.signature.value_as_hex()

        return {
            "header": self.interpret_header(seal.header),
            "fields": fields,
            "image_bytes": image_data,
            "signature_hex": seal.signature.value_as_hex() if seal.signature else None,
            "signed_data_hex": seal.signed_data.hex().upper(),
        }

    # -- Formatting --

    def _field_label(self, key: str) -> str:
        return self.field_labels.get(key, key)

    def _format_value(self, value: Any) -> str:
        if isinstance(value, bool):
            return "Yes" if value else "No"
        return str(value)

    def format(self, result: dict[str, Any]) -> str:
        lines: list[str] = []
        header = result["header"]
        fields = result["fields"]

        lines.append("=" * 65)
        lines.append(f"  {self.name} — Decoded Seal")
        lines.append("=" * 65)

        lines.append("\n  Header")
        lines.append("  " + "-" * 45)
        for key, value in header.items():
            label = HEADER_LABELS.get(key) or key
            lines.append(f"  {f'{label}:':<30}{value}")

        lines.append("\n  Fields")
        lines.append("  " + "-" * 45)

        shown: set[str] = set()
        for key in self.display_order:
            if key in fields:
                shown.add(key)
                label = self._field_label(key)
                lines.append(f"  {f'{label}:':<30}{self._format_value(fields[key])}")

        for key, value in fields.items():
            if key not in shown:
                label = self._field_label(key)
                lines.append(f"  {f'{label}:':<30}{self._format_value(value)}")

        lines.append("\n" + "=" * 65)
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Spain Mobile ID (DNI / MiDNI) (document type category 9)
# ---------------------------------------------------------------------------

class SpainMobileIDDecoder(VDSDecoder):
    """Decoder for Spain Mobile ID (DNI / MiDNI) QR codes."""

    name = "Spain Mobile ID"
    document_type_category = 9

    IMAGE_TAG = 0x50
    ADULT_TAG = 0x70

    image_tags = {IMAGE_TAG}

    verification_type_names = {
        7: "Simple",
        8: "Complete",
        9: "Age",
    }

    tag_definitions: dict[int, str] = {
        0x40: "document_number",
        0x42: "date_of_birth",
        0x44: "first_name",
        0x46: "surnames",
        0x48: "sex",
        0x4C: "document_expiry_date",
        0x50: "thumbnail_image",
        0x60: "full_address",
        0x62: "birthplace_line_1",
        0x64: "nationality",
        0x66: "parents_names",
        0x68: "physical_dni_support_number",
        0x70: "is_adult",
        0x72: "address_line_1",
        0x74: "address_line_2",
        0x76: "address_line_3",
        0x78: "birthplace_line_2",
        0x7A: "birthplace_line_3",
        0x80: "data_expiry",
    }

    display_order = [
        "document_number", "first_name", "surnames", "date_of_birth",
        "sex", "document_expiry_date", "is_adult",
        "nationality", "parents_names", "physical_dni_support_number",
        "full_address", "address_line_1", "address_line_2", "address_line_3",
        "birthplace_line_1", "birthplace_line_2", "birthplace_line_3",
        "data_expiry", "thumbnail_image", "signature",
    ]

    def interpret_header(self, header: VDSHeader) -> dict[str, Any]:
        return {
            "version": header.version,
            "issuing_country": header.issuing_country,
            "signer_id": header.signer_id,
            "certificate_reference": header.certificate_reference,
            "document_issue_date": header.document_issue_date,
            "signature_creation_date": header.signature_creation_date,
            "verification_type": self.verification_type_names.get(
                header.document_feature_ref,
                f"Unknown ({header.document_feature_ref})",
            ),
            "document_type": "Spain Mobile ID (DNI / MiDNI)",
        }

    field_labels: dict[str, str] = {
        "document_number": "Document number",
        "first_name": "First name",
        "surnames": "Surnames",
        "date_of_birth": "Date of birth",
        "sex": "Sex",
        "document_expiry_date": "Document expiry date",
        "is_adult": "Is adult (18+)",
        "nationality": "Nationality",
        "parents_names": "Parents' names",
        "physical_dni_support_number": "Physical DNI support #",
        "full_address": "Full address",
        "address_line_1": "Address (1)",
        "address_line_2": "Address (2)",
        "address_line_3": "Address (3)",
        "birthplace_line_1": "Birthplace (1)",
        "birthplace_line_2": "Birthplace (2)",
        "birthplace_line_3": "Birthplace (3)",
        "data_expiry": "QR data expiry",
        "thumbnail_image": "Thumbnail image",
        "signature": "ECDSA signature",
    }

    def interpret_tlv(self, tlv: VDSTlv) -> tuple[str, Any]:
        key = self._tag_key(tlv.tag)
        if tlv.tag == self.IMAGE_TAG:
            return key, f"[{len(tlv.value)} bytes JPEG2000]"
        if tlv.tag == self.ADULT_TAG:
            return key, bool(tlv.value[0])
        text = tlv.value_as_text()
        return key, text if text is not None else tlv.value_as_hex()


# ---------------------------------------------------------------------------
# Decoder registry
# ---------------------------------------------------------------------------

DECODER_REGISTRY: dict[int, type[VDSDecoder]] = {
    SpainMobileIDDecoder.document_type_category: SpainMobileIDDecoder,
}


def get_decoder(seal: VDSSeal) -> VDSDecoder:
    cls = DECODER_REGISTRY.get(seal.header.document_type_category, VDSDecoder)
    return cls()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def sanitize_hex(raw: str) -> str:
    return re.sub(r'[^0-9a-fA-F]', '', raw)


def main():
    parser = argparse.ArgumentParser(
        description="Decode ICAO 9303-13 Visible Digital Seal (VDS) payloads",
        epilog=(
            "examples:\n"
            "  %(prog)s --file payload.bin\n"
            "  %(prog)s --stdin < payload.bin\n"
            "  %(prog)s --file payload.hex --input-format hex\n"
            "  %(prog)s --stdin --open-image < payload.bin\n"
            "  %(prog)s 'dc037581...'\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("hex_payload", nargs="?", default=None, help="Payload as a hex string")
    parser.add_argument("--file", "-f", metavar="PATH", help="Read payload from a file")
    parser.add_argument("--stdin", action="store_true", help="Read payload from stdin")
    parser.add_argument(
        "--input-format", choices=["bin", "hex"], default="bin",
        help="Format for --file/--stdin: bin (default) or hex",
    )

    parser.add_argument("--json", "-j", action="store_true", help="Output as JSON")
    parser.add_argument("--open-image", "-o", action="store_true", help="Open embedded image")
    parser.add_argument("--save-image", "-i", metavar="PATH", help="Save embedded image")

    args = parser.parse_args()

    if not args.file and not args.stdin and args.hex_payload is None:
        parser.error("one of hex_payload, --file, or --stdin is required")
    if args.file and args.stdin:
        parser.error("--file and --stdin are mutually exclusive")
    if args.hex_payload is not None and (args.file or args.stdin):
        parser.error("hex_payload cannot be combined with --file or --stdin")

    if args.file:
        raw = Path(args.file).read_bytes()
    elif args.stdin:
        raw = sys.stdin.buffer.read()
    else:
        raw = args.hex_payload.encode()

    if args.input_format == "hex" or args.hex_payload is not None:
        data = bytes.fromhex(sanitize_hex(raw.decode('ascii', errors='ignore')))
    else:
        data = raw

    if not data:
        parser.error("no input data (empty payload)")

    seal = parse_seal(data)
    decoder = get_decoder(seal)
    result = decoder.interpret(seal)

    if args.save_image and result.get("image_bytes"):
        Path(args.save_image).write_bytes(result["image_bytes"])
        logger.info("Image saved to: %s", args.save_image)

    if args.open_image and result.get("image_bytes"):
        with tempfile.NamedTemporaryFile(suffix=".jp2", delete=False) as tmp:
            tmp.write(result["image_bytes"])
        subprocess.run(["open", tmp.name], check=True)

    if args.json:
        json_output = {k: v for k, v in result.items() if k != "image_bytes"}
        print(json.dumps(json_output, ensure_ascii=False, indent=2))
    else:
        print(decoder.format(result))


if __name__ == "__main__":
    main()
