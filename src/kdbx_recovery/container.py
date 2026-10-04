"""Use PyKeePass's authenticated envelope without its XML/model conversion.

The adapter graph is pinned to PyKeePass 4.1.1.post1. Only the final XML adapter
is omitted; cipher, KDF, header authentication, and block HMACs are unchanged.
"""

import gzip
import io
import struct
import zlib

from construct import Adapter, If, IfThenElse, Struct, Switch, Terminated, this
from pykeepass.kdbx_parsing.kdbx import KDBX
from pykeepass.kdbx_parsing.kdbx4 import Body, DecryptedPayload

MAX_BYTES = 256 * 1024 * 1024
MAX_KEYFILE_BYTES = 1024 * 1024
MAX_MEMORY = 1024 * 1024 * 1024
MAX_ITERATIONS = 100
MAX_AES_ROUNDS = 10_000_000


class RecoveryError(Exception):
    """An error safe to display without exposing decrypted content."""


class BoundedGzip(Adapter):
    def _decode(self, data, context, path):
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        unpacked = decoder.decompress(data, MAX_BYTES + 1)
        if len(unpacked) > MAX_BYTES or decoder.unconsumed_tail:
            raise RecoveryError("The decompressed database exceeds the 256 MiB recovery limit.")
        if not decoder.eof or decoder.unused_data:
            raise RecoveryError("The compressed payload is incomplete or has trailing data.")
        return unpacked

    def _encode(self, data, context, path):
        return gzip.compress(data, mtime=0)


RawBody = Struct(
    *[
        sub
        if sub.name != "payload"
        else "payload"
        / If(
            this._._.decrypt,
            IfThenElse(
                this._.header.value.dynamic_header.compression_flags.data.compression,
                BoundedGzip(DecryptedPayload),
                DecryptedPayload,
            ),
        )
        for sub in Body.subcons
    ]
)
RawKDBX = Struct(
    KDBX.header,
    "body" / Switch(this.header.value.major_version, {4: RawBody}),
    Terminated,
)


def preflight(data: bytes):
    if len(data) > MAX_BYTES:
        raise RecoveryError("The database exceeds the 256 MiB recovery limit.")
    if len(data) < 12 or data[:8] != b"\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5":
        raise RecoveryError("This is not a KDBX database.")
    minor, major = struct.unpack_from("<HH", data, 8)
    if major != 4 or minor > 1:
        raise RecoveryError(
            "Only KDBX 4.0 and 4.1 are supported; KDBX 3 and hardware keys are not."
        )
    try:
        header = KDBX.header.parse(data)
        fields = header.value.dynamic_header
        # Duplicate fields are ambiguous and DynamicDict would discard the earlier one.
        header_fields(header.data)
        params = fields.kdf_parameters.data.dict
        uuid = params["$UUID"].value
        from pykeepass.kdbx_parsing.kdbx4 import kdf_uuids

        if uuid == kdf_uuids["aeskdf"]:
            if not 1 <= params["R"].value <= MAX_AES_ROUNDS:
                raise RecoveryError("AES-KDF rounds exceed the supported recovery limits.")
        elif uuid in (kdf_uuids["argon2"], kdf_uuids["argon2id"]):
            if not (
                8 * 1024 <= params["M"].value <= MAX_MEMORY
                and 1 <= params["I"].value <= MAX_ITERATIONS
                and 1 <= params["P"].value <= 16
                and params["V"].value in (0x10, 0x13)
            ):
                raise RecoveryError("Argon2 parameters exceed the supported recovery limits.")
        else:
            raise RecoveryError("The database uses an unsupported key derivation method.")
        iv_length = 12 if fields.cipher_id.data == "chacha20" else 16
        if len(fields.encryption_iv.data) != iv_length:
            raise RecoveryError("The cipher IV has an invalid length.")
        start, end = header_fields(header.data)[3]
        if header.data[start:end] not in (b"\0" * 4, b"\1\0\0\0"):
            raise RecoveryError("The database uses an unsupported compression setting.")
    except RecoveryError:
        raise
    except Exception:
        raise RecoveryError(
            "The KDBX header is malformed or uses an unsupported feature."
        ) from None
    return header


def header_fields(data: bytes):
    fields = {}
    offset = 12
    while offset < len(data):
        kind, length = struct.unpack_from("<BI", data, offset)
        start = offset + 5
        end = start + length
        if end > len(data) or kind in fields:
            raise RecoveryError("The KDBX header contains invalid or duplicate fields.")
        fields[kind] = (start, end)
        offset = end
        if kind == 0:
            if data[start:end] not in (b"", b"\r\n\r\n") or offset != len(data):
                raise RecoveryError("The KDBX header terminator is invalid.")
            break
    for kind, length in ((4, 32),):
        if kind not in fields or fields[kind][1] - fields[kind][0] != length:
            raise RecoveryError("The KDBX master seed is invalid.")
    return fields


def open_raw(data: bytes, password: str | None, keyfile: bytes | None = None):
    preflight(data)
    try:
        return RawKDBX.parse(
            data,
            password=password,
            keyfile=io.BytesIO(keyfile) if keyfile is not None else None,
            transformed_key=None,
            decrypt=True,
        )
    except RecoveryError:
        raise
    except Exception:
        raise RecoveryError(
            "Could not authenticate and decrypt the database. Check the password and key file; "
            "the file may be damaged or require a hardware key. Nothing was recovered."
        ) from None


def split_payload(payload: bytes) -> tuple[bytes, bytes]:
    if len(payload) > MAX_BYTES:
        raise RecoveryError("The decrypted database exceeds the 256 MiB recovery limit.")
    offset = 0
    required = set()
    while offset + 5 <= len(payload):
        kind, length = struct.unpack_from("<BI", payload, offset)
        offset += 5
        end = offset + length
        if end > len(payload):
            break
        if kind in (1, 2):
            if kind in required:
                raise RecoveryError("The inner header has duplicate stream parameters.")
            required.add(kind)
        if kind == 0:
            if length != 0 or required != {1, 2}:
                break
            return payload[:end], payload[end:]
        offset = end
    raise RecoveryError("The KDBX inner header is malformed.")
