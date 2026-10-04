import hashlib
import io
import os
import struct
import subprocess

import pytest
from lxml import etree
from pykeepass import PyKeePass

from kdbx_recovery.container import RecoveryError, open_raw, split_payload
from kdbx_recovery.recovery import INVALID_SCALARS, recover_bytes, recover_file, repair_xml

from .conftest import FIXTURES, PASSWORD, build_record


def inject(xml, scalar=0):
    return xml.replace(b"<Name>", b"<Name>before" + chr(scalar).encode() + b"after", 1)


def expected_without_nul(payload):
    inner, xml = split_payload(payload)
    return inner + xml.replace(b"\0", b"")


def ordinary_open(data, password=PASSWORD, keyfile=None):
    return PyKeePass(
        io.BytesIO(data),
        password=password,
        keyfile=io.BytesIO(keyfile) if keyfile is not None else None,
    )


def test_real_keeforge_reproduction():
    source = (FIXTURES / "keeforge-nul.kdbx").read_bytes()
    with pytest.raises(etree.XMLSyntaxError):
        ordinary_open(source)
    original = open_raw(source, PASSWORD)
    repaired, report = recover_bytes(source, PASSWORD)
    assert report.removed == {0: 1}
    assert open_raw(repaired, PASSWORD).body.payload == expected_without_nul(original.body.payload)
    kp = ordinary_open(repaired)
    entry = kp.find_entries(title="Issue 181", first=True)
    if entry is None:
        entry = next(e for e in kp.entries if "Example heading" in (e.notes or ""))
    assert "Example body" in entry.notes
    assert "Example heading" in entry.notes
    assert "\0" not in entry.notes


@pytest.mark.parametrize("scalar", INVALID_SCALARS)
def test_each_forbidden_scalar(make_database, scalar):
    damaged, payload = make_database(lambda xml: inject(xml, scalar))
    repaired, report = recover_bytes(damaged, PASSWORD)
    inner, xml = split_payload(payload)
    expected = inner + xml.replace(chr(scalar).encode(), b"")
    assert open_raw(repaired, PASSWORD).body.payload == expected
    assert report.removed == {scalar: 1}
    assert ordinary_open(repaired).root_group.name.startswith("beforeafter")


@pytest.mark.parametrize("cipher", ["aes256", "chacha20", "twofish"])
@pytest.mark.parametrize("kdf", ["aeskdf", "argon2", "argon2id"])
@pytest.mark.parametrize("compression", [False, True])
def test_cipher_kdf_compression_matrix(make_database, cipher, kdf, compression):
    damaged, payload = make_database(inject, cipher=cipher, kdf=kdf, compression=compression)
    repaired, _ = recover_bytes(damaged, PASSWORD)
    original = open_raw(damaged, PASSWORD)
    result = open_raw(repaired, PASSWORD)
    assert result.body.payload == expected_without_nul(payload)
    fields_before = original.header.value.dynamic_header
    fields_after = result.header.value.dynamic_header
    assert fields_after.master_seed.data != fields_before.master_seed.data
    assert fields_after.encryption_iv.data != fields_before.encryption_iv.data
    for key in fields_before:
        if key not in ("master_seed", "encryption_iv"):
            assert fields_before[key] == fields_after[key]
    kp_before = ordinary_open(make_database(cipher=cipher, kdf=kdf, compression=compression)[0])
    kp_after = ordinary_open(repaired)
    assert [(e.uuid, e.password) for e in kp_after.entries] == [
        (e.uuid, e.password) for e in kp_before.entries
    ]
    assert kp_after.binaries == kp_before.binaries
    assert (
        kp_after.find_entries(title="Protected Custom", first=True).get_custom_property("API Token")
        == "custom-secret"
    )


@pytest.mark.parametrize(
    "name,password,keyfile",
    [
        ("rich", PASSWORD, None),
        ("twofish", "foreign-twofish", None),
        ("chacha20", "foreign-chacha20", None),
        ("keyfile", "demo", "keyfile.key"),
    ],
)
def test_independent_foreign_fixtures(name, password, keyfile):
    key = (FIXTURES / keyfile).read_bytes() if keyfile else None
    record = open_raw((FIXTURES / f"{name}.kdbx").read_bytes(), password, key)
    inner, xml = split_payload(record.body.payload)
    record.body.payload = inner + inject(xml)
    damaged = build_record(record, password, key)
    recovered, _ = recover_bytes(damaged, password, key)
    assert open_raw(recovered, password, key).body.payload == inner + inject(xml).replace(
        b"\0", b""
    )
    assert ordinary_open(recovered, password, key).entries


@pytest.mark.parametrize(
    "key",
    [b"k" * 32, b"6b" * 32, b"arbitrary key file bytes", (FIXTURES / "keyfile.key").read_bytes()],
)
@pytest.mark.parametrize("password", [PASSWORD, None, ""])
def test_credentials_matrix(make_database, key, password):
    damaged, _ = make_database(inject, password=password, keyfile=key)
    recovered, _ = recover_bytes(damaged, password, key)
    assert ordinary_open(recovered, password, key).entries
    with pytest.raises(RecoveryError, match="authenticate"):
        recover_bytes(damaged, password, b"wrong key file")


def test_all_paths_history_unknown_whitespace_and_protected_ciphertext(make_database):
    fragment = (
        b'<Unknown Vendor="a\0b"><Value Protected="True">c2VjcmV0</Value>'
        b"<Text>unknown\0content</Text></Unknown>"
    )

    def transform(xml):
        xml = xml.replace(b"<Name>", b"<Name> \0 ", 1)
        xml = xml.replace(b"</Group>", b"<Notes>group\0notes</Notes><Tags>a\0b</Tags></Group>", 1)
        xml = xml.replace(b"<History>", b"<History>\0", 1)
        xml = xml.replace(b"<Key>", b"<Key>\0", 1)
        xml = xml.replace(b"</Root>", fragment + b"</Root>", 1)
        return xml.replace(b"</KeePassFile>", b"<!-- keep CR\r\n TAB\t -->\n</KeePassFile>")

    damaged, payload = make_database(transform)
    recovered, report = recover_bytes(damaged, PASSWORD)
    inner, xml = split_payload(payload)
    assert sum(report.removed.values()) >= 6
    assert open_raw(recovered, PASSWORD).body.payload == inner + xml.replace(b"\0", b"")
    assert b'Vendor="ab"' in open_raw(recovered, PASSWORD).body.payload
    assert b'Protected="True">c2VjcmV0' in open_raw(recovered, PASSWORD).body.payload
    assert b"keep CR\r\n TAB\t" in open_raw(recovered, PASSWORD).body.payload


def test_multiple_scalars_and_large_valid_unicode_notes(make_database):
    notes = ("日😀café<&>\t\r\n" * 100_000).encode()

    def transform(xml):
        return xml.replace(
            b"</Root>",
            b"<Extra>"
            + notes.replace(b"<", b"&lt;").replace(b"&", b"&amp;")
            + b"\0\x01\0</Extra></Root>",
        )

    damaged, payload = make_database(transform)
    recovered, report = recover_bytes(damaged, PASSWORD)
    inner, xml = split_payload(payload)
    assert report.removed == {0: 2, 1: 1}
    assert open_raw(recovered, PASSWORD).body.payload == inner + xml.replace(b"\0", b"").replace(
        b"\x01", b""
    )


def test_unknown_inner_header_items_and_binary_nuls_are_preserved(make_database):
    def extend(inner):
        return inner[:-5] + struct.pack("<BI", 42, 5) + b"a\0b\0c" + inner[-5:]

    damaged, payload = make_database(inject, inner_transform=extend)
    recovered, report = recover_bytes(damaged, PASSWORD)
    inner, xml = split_payload(payload)
    assert report.removed == {0: 1}
    assert open_raw(recovered, PASSWORD).body.payload == inner + xml.replace(b"\0", b"")
    assert b"a\0b\0c" in open_raw(recovered, PASSWORD).body.payload


def test_healthy_database_has_no_output(make_database, tmp_path):
    healthy, _ = make_database()
    assert recover_bytes(healthy, PASSWORD)[0] is None
    source, output = tmp_path / "original", tmp_path / "recovered"
    source.write_bytes(healthy)
    result = recover_file(source, output, PASSWORD)
    assert result.removed == {}
    assert not output.exists()
    assert source.read_bytes() == healthy


def test_valid_unicode_boundaries_are_untouched():
    chars = "\t\r\n" + "".join(
        chr(i) for i in [0x20, 0x7F, 0xD7FF, 0xE000, 0xFDD0, 0xFFFD, 0x10000, 0x1FFFE, 0x10FFFF]
    )
    xml = (
        f"<KeePassFile><Meta/><Root><Group><Notes>{chars}</Notes></Group></Root></KeePassFile>"
    ).encode()
    assert repair_xml(xml) == (xml, {})


def test_output_published_and_input_unchanged(make_database, tmp_path):
    damaged, expected = make_database(inject)
    source, output = tmp_path / "original.kdbx", tmp_path / "recovered.kdbx"
    source.write_bytes(damaged)
    report = recover_file(source, output, PASSWORD)
    assert source.read_bytes() == damaged
    assert report.input_sha256 == hashlib.sha256(damaged).hexdigest()
    assert report.output_sha256 == hashlib.sha256(output.read_bytes()).hexdigest()
    assert open_raw(output.read_bytes(), PASSWORD).body.payload == expected_without_nul(expected)
    assert ordinary_open(output.read_bytes()).entries
    assert not list(tmp_path.glob(".kdbx-recovery-*"))
    if os.name != "nt":
        assert output.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize(
    "existing", ["file", "input", "symlink", "hardlink", "broken-symlink", "directory"]
)
def test_never_overwrites(make_database, tmp_path, existing):
    damaged, _ = make_database(inject)
    source = tmp_path / "input"
    source.write_bytes(damaged)
    output = tmp_path / "output"
    if existing == "input":
        output = source
    elif existing == "file":
        output.write_bytes(b"keep this")
    elif existing == "directory":
        output.mkdir()
    elif existing == "hardlink":
        os.link(source, output)
    else:
        try:
            output.symlink_to(source if existing == "symlink" else tmp_path / "absent")
        except OSError:
            pytest.skip("Symlink privilege unavailable")
    with pytest.raises(RecoveryError, match="never overwritten"):
        recover_file(source, output, PASSWORD)
    assert source.read_bytes() == damaged
    if existing == "file":
        assert output.read_bytes() == b"keep this"


@pytest.mark.parametrize("cipher", ["aes256", "twofish", "chacha20"])
@pytest.mark.parametrize("kdf", ["aeskdf", "argon2", "argon2id"])
@pytest.mark.parametrize("compression", [False, True])
def test_keepassxc_reopens_and_exports_exact_text(
    make_database, tmp_path, cipher, kdf, compression
):
    executable = os.environ.get("KEEPASSXC_CLI")
    if not executable:
        pytest.skip("Set KEEPASSXC_CLI to require independent interoperability checks")
    damaged, _ = make_database(inject, cipher=cipher, kdf=kdf, compression=compression)
    recovered, _ = recover_bytes(damaged, PASSWORD)
    path = tmp_path / "recovered.kdbx"
    path.write_bytes(recovered)
    result = subprocess.run(
        [executable, "export", "-q", str(path)],
        input=PASSWORD + "\n",
        text=True,
        capture_output=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    tree = etree.fromstring(result.stdout.encode())
    assert tree.findtext("Root/Group/Name").startswith("beforeafter")
    assert tree.xpath('//Entry/String[Key="API Token"]/Value/text()') == [
        "custom-secret",
        "custom-secret",
    ]
    assert b"</KeePassFile>" in result.stdout.encode()


def test_protected_nul_is_preserved_exactly():
    from base64 import b64decode

    from Cryptodome.Cipher import ChaCha20, Salsa20

    record = open_raw((FIXTURES / "protected-nul.kdbx").read_bytes(), PASSWORD)
    inner, xml = split_payload(record.body.payload)
    record.body.payload = inner + inject(xml)
    recovered, report = recover_bytes(build_record(record), PASSWORD)
    assert report.removed == {0: 1}
    result = open_raw(recovered, PASSWORD)
    assert result.body.payload == inner + inject(xml).replace(b"\0", b"")
    # Decode the original inner stream independently, including NUL inside protected values.
    offset = 0
    fields = {}
    while offset < len(inner):
        kind, length = struct.unpack_from("<BI", inner, offset)
        offset += 5
        fields[kind] = inner[offset : offset + length]
        offset += length
    stream_id = struct.unpack("<I", fields[1])[0]
    key = fields[2]
    if stream_id == 3:
        digest = hashlib.sha512(key).digest()
        cipher = ChaCha20.new(key=digest[:32], nonce=digest[32:44])
    else:
        assert stream_id == 2
        cipher = Salsa20.new(
            key=hashlib.sha256(key).digest(), nonce=b"\xe8\x30\x09\x4b\x97\x20\x5d\x2a"
        )
    tree = etree.fromstring(split_payload(result.body.payload)[1])
    values = [
        cipher.decrypt(b64decode(e.text or "")) for e in tree.xpath('//Value[@Protected="True"]')
    ]
    assert b"Example heading\0\r\nExample body" in values
