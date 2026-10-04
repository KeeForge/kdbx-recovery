import copy
import io
from pathlib import Path

import pytest
from construct import Container
from pykeepass.kdbx_parsing.kdbx import KDBX
from pykeepass.kdbx_parsing.kdbx4 import kdf_uuids

from kdbx_recovery.container import RawKDBX, open_raw, split_payload

FIXTURES = Path(__file__).parent / "fixtures"
PASSWORD = "testpassword123"


def build_record(record, password=PASSWORD, keyfile=None):
    return RawKDBX.build(
        record,
        password=password,
        keyfile=io.BytesIO(keyfile) if keyfile is not None else None,
        transformed_key=None,
        decrypt=True,
    )


def refresh_header(record):
    record.header = KDBX.header.parse(KDBX.header.build({"value": record.header.value}))


def set_kdf(record, name):
    if name == "aeskdf":
        spec = [("$UUID", 0x42, kdf_uuids[name]), ("S", 0x42, b"s" * 32), ("R", 0x05, 3)]
    else:
        spec = [
            ("$UUID", 0x42, kdf_uuids[name]),
            ("S", 0x42, b"s" * 32),
            ("I", 0x05, 2),
            ("M", 0x05, 64 * 1024),
            ("P", 0x04, 1),
            ("V", 0x04, 0x13),
        ]
    record.header.value.dynamic_header.kdf_parameters.data.dict = Container(
        {
            key: Container(
                type=kind, key=key, value=value, next_byte=0 if i == len(spec) - 1 else 0x42
            )
            for i, (key, kind, value) in enumerate(spec)
        }
    )
    refresh_header(record)


@pytest.fixture(scope="session")
def rich():
    record = open_raw((FIXTURES / "rich.kdbx").read_bytes(), PASSWORD)
    set_kdf(record, "aeskdf")
    return record


@pytest.fixture
def make_database(rich):
    def make(
        transform=lambda xml: xml,
        *,
        cipher="aes256",
        kdf="aeskdf",
        compression=True,
        password=PASSWORD,
        keyfile=None,
        inner_transform=lambda inner: inner,
    ):
        record = copy.deepcopy(rich)
        set_kdf(record, kdf)
        record.header.value.dynamic_header.cipher_id.data = cipher
        record.header.value.dynamic_header.encryption_iv.data = b"i" * (
            12 if cipher == "chacha20" else 16
        )
        record.header.value.dynamic_header.compression_flags.data.compression = compression
        refresh_header(record)
        inner, xml = split_payload(record.body.payload)
        expected = inner_transform(inner) + transform(xml)
        record.body.payload = expected
        return build_record(record, password, keyfile), expected

    return make
