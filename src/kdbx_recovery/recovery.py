import hashlib
import io
import os
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from lxml import etree

from .container import (
    MAX_BYTES,
    MAX_KEYFILE_BYTES,
    RawKDBX,
    RecoveryError,
    header_fields,
    open_raw,
    split_payload,
)

INVALID_SCALARS = (*range(0, 9), 11, 12, *range(14, 32), 0xFFFE, 0xFFFF)
REMOVALS = dict.fromkeys(INVALID_SCALARS)


@dataclass(frozen=True)
class RecoveryResult:
    removed: dict[int, int]
    input_sha256: str
    output_sha256: str | None


def repair_xml(xml: bytes) -> tuple[bytes, dict[int, int]]:
    try:
        text = xml.decode("utf-8")
    except UnicodeDecodeError:
        raise RecoveryError("The XML is not valid UTF-8; this tool cannot recover it.") from None
    counts = Counter(ord(char) for char in text if ord(char) in REMOVALS)
    repaired = text.translate(REMOVALS).encode("utf-8")
    validate_xml(repaired)
    return repaired, dict(sorted(counts.items()))


def validate_xml(xml: bytes):
    try:
        parser = etree.XMLParser(
            resolve_entities=False, load_dtd=False, no_network=True, recover=False, huge_tree=True
        )
        tree = etree.parse(io.BytesIO(xml), parser)
        encoding = (tree.docinfo.encoding or "UTF-8").upper()
        if tree.docinfo.doctype or encoding != "UTF-8":
            raise RecoveryError("DTD declarations and non-UTF-8 XML are not supported.")
        root = tree.getroot()
        if (
            root.tag != "KeePassFile"
            or len(root.findall("Meta")) != 1
            or len(root.findall("Root")) != 1
            or root.find("Root/Group") is None
        ):
            raise RecoveryError("The repaired XML is not a KeePass database document.")
    except RecoveryError:
        raise
    except etree.XMLSyntaxError:
        raise RecoveryError(
            "The XML still has structural errors after removing invalid characters. "
            "This tool only repairs the invalid-character bug."
        ) from None


def recover_bytes(
    data: bytes, password: str | None, keyfile: bytes | None = None
) -> tuple[bytes | None, RecoveryResult]:
    if keyfile is not None and (not keyfile or len(keyfile) > MAX_KEYFILE_BYTES):
        raise RecoveryError("The key file must be nonempty and no larger than 1 MiB.")
    database = open_raw(data, password, keyfile)
    inner_header, xml = split_payload(database.body.payload)
    repaired, counts = repair_xml(xml)
    digest = hashlib.sha256(data).hexdigest()
    if not counts:
        return None, RecoveryResult({}, digest, None)

    # Keep inner stream parameters/ciphertext and all untouched XML bytes intact.
    database.body.payload = inner_header + repaired
    fresh_header = bytearray(database.header.data)
    fields = header_fields(fresh_header)
    for kind in (4, 7):
        start, end = fields[kind]
        fresh_header[start:end] = os.urandom(end - start)
    from pykeepass.kdbx_parsing.kdbx import KDBX

    database.header = KDBX.header.parse(bytes(fresh_header))
    try:
        recovered = RawKDBX.build(
            database,
            password=password,
            keyfile=io.BytesIO(keyfile) if keyfile is not None else None,
            transformed_key=database.body.transformed_key,
            decrypt=True,
        )
    except Exception:
        raise RecoveryError(
            "Could not build the recovered database. No output was written."
        ) from None
    verified = open_raw(recovered, password, keyfile)
    if verified.body.payload != inner_header + repaired:
        raise RecoveryError("Recovered payload verification failed. No output was written.")
    _, verified_xml = split_payload(verified.body.payload)
    validate_xml(verified_xml)
    return recovered, RecoveryResult(counts, digest, hashlib.sha256(recovered).hexdigest())


def read_limited(path: Path, limit: int) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise RecoveryError("The input file exceeds the supported recovery size limit.")
    return data


def recover_file(
    source: Path, output: Path | None, password: str | None, keyfile_path: Path | None = None
) -> RecoveryResult:
    source = Path(source)
    output = Path(output) if output is not None else None
    if output is not None:
        if source.resolve() == output.resolve() or output.exists() or output.is_symlink():
            raise RecoveryError("Choose a new output file. Existing files are never overwritten.")
    data = read_limited(source, MAX_BYTES)
    keyfile = read_limited(Path(keyfile_path), MAX_KEYFILE_BYTES) if keyfile_path else None
    if output is not None and keyfile_path and output.resolve() == Path(keyfile_path).resolve():
        raise RecoveryError("The output cannot be the key file.")
    recovered, result = recover_bytes(data, password, keyfile)
    if output is None or recovered is None:
        return result

    descriptor, temporary_name = tempfile.mkstemp(prefix=".kdbx-recovery-", dir=output.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(recovered)
            stream.flush()
            os.fsync(stream.fileno())
        on_disk = read_limited(temporary, MAX_BYTES)
        if on_disk != recovered:
            raise RecoveryError("Output verification failed; the destination may be full.")
        verified = open_raw(on_disk, password, keyfile)
        _, xml = split_payload(verified.body.payload)
        validate_xml(xml)
        if hashlib.sha256(read_limited(source, MAX_BYTES)).hexdigest() != result.input_sha256:
            raise RecoveryError("The input changed during recovery. No output was published.")
        # A hard link publishes a complete encrypted file atomically and never replaces a path.
        os.link(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)
    return result
