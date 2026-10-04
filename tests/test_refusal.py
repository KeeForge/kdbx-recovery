import gzip
import struct

import pytest
from construct import GreedyBytes

from kdbx_recovery import container, recovery
from kdbx_recovery.container import (
    BoundedGzip,
    RecoveryError,
    header_fields,
    open_raw,
    split_payload,
)
from kdbx_recovery.recovery import recover_bytes, recover_file, repair_xml

from .conftest import PASSWORD, refresh_header
from .test_recovery import inject


@pytest.mark.parametrize(
    "where",
    [
        "header-hash",
        "header-hmac",
        "payload-hmac",
        "payload-data",
        "terminal-hmac",
        "terminal-size",
        "truncated",
        "trailing",
    ],
)
def test_integrity_failures_never_produce_output(make_database, tmp_path, where):
    damaged, _ = make_database(inject)
    header = container.preflight(damaged)
    end = header.length
    data = bytearray(damaged)
    if where == "header-hash":
        data[end] ^= 1
    elif where == "header-hmac":
        data[end + 32] ^= 1
    elif where == "payload-hmac":
        data[end + 64] ^= 1
    elif where == "payload-data":
        data[end + 100] ^= 1
    elif where == "terminal-hmac":
        data[-36] ^= 1
    elif where == "terminal-size":
        data[-1] = 1
    elif where == "truncated":
        del data[-10:]
    elif where == "trailing":
        data += b"unexpected trailing data"
    source, output = tmp_path / "original", tmp_path / "recovered"
    source.write_bytes(data)
    with pytest.raises(RecoveryError):
        recover_file(source, output, PASSWORD)
    assert source.read_bytes() == data
    assert not output.exists()
    assert not list(tmp_path.glob(".kdbx-recovery-*"))


def test_wrong_password(make_database, tmp_path):
    data, _ = make_database(inject)
    source, output = tmp_path / "original", tmp_path / "output"
    source.write_bytes(data)
    with pytest.raises(RecoveryError, match="authenticate"):
        recover_file(source, output, "wrong")
    assert not output.exists()
    assert source.read_bytes() == data


@pytest.mark.parametrize(
    "xml",
    [
        b"<KeePassFile><Meta/><Root><Group><Notes>private-secret\0</Group></Root></KeePassFile>",
        b"<KeePassFile><Meta/><Root><Group><Notes>&#0;</Notes></Group></Root></KeePassFile>",
        b"<KeePassFile><Meta/><Root><Group><Notes>\xff</Notes></Group></Root></KeePassFile>",
        b"<Other><Meta/><Root><Group/></Root></Other>",
        b"<KeePassFile><Root><Group/></Root></KeePassFile>",
        b"<KeePassFile><Meta/><Root/></KeePassFile>",
        b"<KeePassFile><Meta/><Meta/><Root><Group/></Root></KeePassFile>",
        b'<?xml version="1.0" encoding="ISO-8859-1"?>'
        b"<KeePassFile><Meta/><Root><Group/></Root></KeePassFile>",
        b'<!DOCTYPE KeePassFile [<!ENTITY secret SYSTEM "file:///etc/passwd">]><KeePassFile><Meta/><Root><Group><Notes>&secret;</Notes></Group></Root></KeePassFile>',
    ],
)
def test_xml_refusal_is_strict_and_redacted(xml):
    with pytest.raises(RecoveryError) as error:
        repair_xml(xml)
    assert "private-secret" not in str(error.value)
    assert "passwd" not in str(error.value)


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"not a database",
        b"\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5" + struct.pack("<HH", 1, 3),
        b"\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5" + struct.pack("<HH", 2, 4),
    ],
)
def test_unsupported_formats(data):
    with pytest.raises(RecoveryError):
        recover_bytes(data, PASSWORD)


@pytest.mark.parametrize("parameter,value", [("R", 0), ("R", 10_000_001)])
def test_aes_limits_before_kdf(make_database, parameter, value, monkeypatch):
    data, _ = make_database(inject)
    record = open_raw(data, PASSWORD)
    record.header.value.dynamic_header.kdf_parameters.data.dict[parameter].value = value
    refresh_header(record)
    monkeypatch.setattr(container.RawKDBX, "parse", lambda *a, **k: pytest.fail("KDF must not run"))
    with pytest.raises(RecoveryError, match="limits"):
        container.preflight(record.header.data)


@pytest.mark.parametrize(
    "parameter,value",
    [("M", 1024), ("M", 1024**3 + 1), ("I", 0), ("I", 101), ("P", 0), ("P", 17), ("V", 42)],
)
def test_argon_limits_before_kdf(make_database, parameter, value):
    data, _ = make_database(inject, kdf="argon2id")
    record = open_raw(data, PASSWORD)
    record.header.value.dynamic_header.kdf_parameters.data.dict[parameter].value = value
    refresh_header(record)
    with pytest.raises(RecoveryError, match="limits"):
        container.preflight(record.header.data)


def test_unknown_kdf(make_database):
    data, _ = make_database(inject)
    record = open_raw(data, PASSWORD)
    record.header.value.dynamic_header.kdf_parameters.data.dict["$UUID"].value = b"x" * 16
    refresh_header(record)
    with pytest.raises(RecoveryError, match="unsupported key derivation"):
        container.preflight(record.header.data)


def test_unknown_cipher_and_malformed_header(make_database):
    data, _ = make_database(inject)
    header = container.preflight(data)
    start, end = header_fields(header.data)[2]
    modified = bytearray(data)
    modified[start:end] = b"x" * 16
    with pytest.raises(RecoveryError, match="header"):
        container.preflight(modified)
    with pytest.raises(RecoveryError, match="header"):
        container.preflight(data[:20])


def test_duplicate_header_fields(make_database):
    data, _ = make_database(inject)
    header = container.preflight(data)
    end_start, _ = header_fields(header.data)[0]
    duplicate = (
        header.data[: end_start - 5]
        + struct.pack("<BI", 4, 32)
        + b"x" * 32
        + header.data[end_start - 5 :]
    )
    with pytest.raises(RecoveryError, match="duplicate"):
        header_fields(duplicate)


def test_bad_header_terminator_and_master_seed(make_database):
    data, _ = make_database(inject)
    header = container.preflight(data)
    start, end = header_fields(header.data)[0]
    with pytest.raises(RecoveryError, match="terminator"):
        header_fields(header.data[:start] + b"bad!")
    short_seed = b"123456789012" + struct.pack("<BI", 4, 1) + b"s" + struct.pack("<BI", 0, 0)
    with pytest.raises(RecoveryError, match="master seed"):
        header_fields(short_seed)


@pytest.mark.parametrize(
    "inner",
    [
        b"",
        struct.pack("<BI", 0, 0),
        struct.pack("<BI", 3, 100) + b"short",
        struct.pack("<BI", 1, 0) * 2,
    ],
)
def test_bad_inner_header(inner):
    with pytest.raises(RecoveryError, match="inner header"):
        split_payload(inner)


def test_bounded_decompression(monkeypatch):
    monkeypatch.setattr(container, "MAX_BYTES", 100)
    codec = BoundedGzip(GreedyBytes)
    with pytest.raises(RecoveryError, match="decompressed"):
        codec._decode(gzip.compress(b"x" * 101), None, None)
    for data in (
        gzip.compress(b"ok")[:-4],
        gzip.compress(b"ok") + b"trailing",
        gzip.compress(b"ok") * 2,
    ):
        with pytest.raises(RecoveryError, match="compressed payload"):
            codec._decode(data, None, None)
    assert codec._decode(gzip.compress(b"x" * 100), None, None) == b"x" * 100


def test_size_and_keyfile_limits(make_database, monkeypatch, tmp_path):
    damaged, _ = make_database(inject)
    with pytest.raises(RecoveryError, match="key file"):
        recover_bytes(damaged, PASSWORD, b"")
    with pytest.raises(RecoveryError, match="key file"):
        recover_bytes(damaged, PASSWORD, b"x" * (container.MAX_KEYFILE_BYTES + 1))
    monkeypatch.setattr(container, "MAX_BYTES", 10)
    with pytest.raises(RecoveryError, match="exceeds"):
        container.preflight(damaged)
    with pytest.raises(RecoveryError, match="exceeds"):
        split_payload(b"x" * 11)
    path = tmp_path / "large"
    path.write_bytes(b"x" * 11)
    with pytest.raises(RecoveryError, match="size limit"):
        recovery.read_limited(path, 10)


def test_build_and_verification_failures(make_database, monkeypatch):
    damaged, _ = make_database(inject)

    def fail(*args, **kwargs):
        raise ValueError("private decrypted text")

    monkeypatch.setattr(recovery.RawKDBX, "build", fail)
    with pytest.raises(RecoveryError, match="build") as error:
        recover_bytes(damaged, PASSWORD)
    assert "private" not in str(error.value)


def test_verify_payload_mismatch(make_database, monkeypatch):
    damaged, _ = make_database(inject)
    original = recovery.open_raw
    count = 0

    def changed(data, *args, **kwargs):
        nonlocal count
        count += 1
        record = original(data, *args, **kwargs)
        if count == 2:
            record.body.payload += b"changed"
        return record

    monkeypatch.setattr(recovery, "open_raw", changed)
    with pytest.raises(RecoveryError, match="payload verification"):
        recover_bytes(damaged, PASSWORD)


def test_check_does_not_write(make_database, tmp_path):
    data, _ = make_database(inject)
    source = tmp_path / "source"
    source.write_bytes(data)
    report = recover_file(source, None, PASSWORD)
    assert report.removed == {0: 1}
    assert list(tmp_path.iterdir()) == [source]
    assert source.read_bytes() == data


@pytest.mark.parametrize(
    "fault", ["fsync", "disk-verification", "input-changed", "output-race", "interrupt"]
)
def test_file_failures_leave_input_and_no_partial_output(
    make_database, tmp_path, monkeypatch, fault
):
    data, _ = make_database(inject)
    source, output = tmp_path / "source", tmp_path / "output"
    source.write_bytes(data)
    if fault in ("fsync", "interrupt"):

        def fail(*args):
            if fault == "interrupt":
                raise KeyboardInterrupt
            raise OSError("Disk full")

        monkeypatch.setattr(recovery.os, "fsync", fail)
    elif fault == "disk-verification":
        original = recovery.read_limited

        def corrupt(path, limit):
            read = original(path, limit)
            return read + b"corrupt" if path.name.startswith(".kdbx-recovery-") else read

        monkeypatch.setattr(recovery, "read_limited", corrupt)
    elif fault == "input-changed":
        original = recovery.os.fsync

        def alter(fd):
            original(fd)
            source.write_bytes(b"changed externally")

        monkeypatch.setattr(recovery.os, "fsync", alter)
    else:
        original = recovery.os.link

        def race(src, dst):
            output.write_bytes(b"keep external file")
            original(src, dst)

        monkeypatch.setattr(recovery.os, "link", race)
    with pytest.raises((RecoveryError, OSError, KeyboardInterrupt)):
        recover_file(source, output, PASSWORD)
    assert not list(tmp_path.glob(".kdbx-recovery-*"))
    if fault == "output-race":
        assert output.read_bytes() == b"keep external file"
    else:
        assert not output.exists()
    assert source.read_bytes() == (b"changed externally" if fault == "input-changed" else data)


def test_missing_destination_and_source(make_database, tmp_path):
    data, _ = make_database(inject)
    source = tmp_path / "source"
    source.write_bytes(data)
    with pytest.raises(OSError):
        recover_file(source, tmp_path / "absent" / "out", PASSWORD)
    with pytest.raises(OSError):
        recover_file(tmp_path / "missing", tmp_path / "out", PASSWORD)


def test_invalid_iv_and_compression(make_database):
    data, _ = make_database(inject)
    record = open_raw(data, PASSWORD)
    record.header.value.dynamic_header.encryption_iv.data = b"short"
    refresh_header(record)
    with pytest.raises(RecoveryError, match="IV"):
        container.preflight(record.header.data)
    data, _ = make_database(inject)
    header = container.preflight(data)
    start, end = header_fields(header.data)[3]
    malformed = bytearray(header.data)
    malformed[start:end] = b"\2\0\0\0"
    with pytest.raises(RecoveryError, match="compression"):
        container.preflight(malformed)


def test_authenticated_decompression_limit(make_database, monkeypatch):
    damaged, _ = make_database(
        lambda xml: inject(xml).replace(
            b"</Root>", b"<Extra>" + b"x" * 100_000 + b"</Extra></Root>"
        )
    )
    assert len(damaged) < 100_000
    monkeypatch.setattr(container, "MAX_BYTES", 80_000)
    with pytest.raises(RecoveryError, match="decompressed"):
        recover_bytes(damaged, PASSWORD)


def test_keyfile_is_never_output(make_database, tmp_path):
    # An absent key path is not itself a valid key file and must never be created as output.
    damaged, _ = make_database(inject)
    source, key = tmp_path / "source", tmp_path / "key"
    source.write_bytes(damaged)
    with pytest.raises(OSError):
        recover_file(source, key, PASSWORD, key)
    assert not key.exists()
