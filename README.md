# KeeForge KDBX recovery

Recover a KeePass database that stopped opening after KeeForge saved notes or other text containing an invisible NUL or another XML-invalid character ([KeeForge issue #181](https://github.com/KeeForge/KeeForge/issues/181)). The tool removes those characters, keeps the remaining content, and creates a separately encrypted, verified `.kdbx` file.

**Try a readable KeeForge backup or your cloud provider's earlier file version first.** This tool helps when those aren't available or you need the latest changes from the damaged file. Updating KeeForge prevents new corruption; it does not repair an already damaged file.

Everything runs locally on your computer. There are no uploads, telemetry, or network requests during recovery. You need the same password and key file you normally use to open the database. The tool cannot recover a lost password.

## Install

Requires Python 3.10 or later on macOS, Windows, or Linux. Download the [repository ZIP](https://github.com/KeeForge/kdbx-recovery/archive/refs/heads/main.zip), extract it, and open a terminal in the extracted folder.

macOS / Linux:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/kdbx-recover --help
```

Windows (PowerShell):

```powershell
py -m venv .venv
.venv\Scripts\python -m pip install .
.venv\Scripts\kdbx-recover --help
```

Installation downloads the Python dependencies. Recovery itself is offline. You can disconnect the computer from the internet after installation. If you use [uv](https://docs.astral.sh/uv/), you can instead install with `uv tool install .` and run `kdbx-recover` directly.

## Recover

1. Copy the damaged database from your phone or cloud storage to your computer. Keep the original.
2. Run the tool with a **new** output filename. It prompts for the password without showing it:

   ```sh
   .venv/bin/kdbx-recover damaged.kdbx --output recovered.kdbx
   ```

   On Windows, replace `.venv/bin/kdbx-recover` with `.venv\Scripts\kdbx-recover`.
3. If you normally use a key file, add `--keyfile your-keyfile.key`. A key-file-only database also needs `--keyfile-only`; an empty password is different from having no password component.
4. The tool reports counts such as `U+0000: 1`, without printing any entries or passwords. Only the invalid characters are removed. For example, `heading<NUL>body` becomes `headingbody`; the text after NUL is kept.
5. Open the recovered file in KeeForge or KeePassXC. Check the latest edits, entry history, and attachments. Then add or reconnect that recovered file in KeeForge. Keep the original damaged file and your backups until you're satisfied.

Use `--check` instead of `--output recovered.kdbx` to authenticate the database and report what would be removed without writing a file. No output is created for a database without XML-invalid characters.

For scripted use, `--password-stdin` reads one line from standard input. Prefer the hidden prompt; never put your real password in a command-line argument or shell history. Embedded newlines in a password require the interactive prompt.

## What it preserves and what it refuses

- Supports KDBX **4.0 and 4.1**, AES-256, ChaCha20, Twofish, AES-KDF, Argon2d, and Argon2id, with or without compression, plus password and optional key-file credentials.
- Verifies the header hash, header HMAC, **every encrypted payload block including the terminating block**, and complete input consumption before recovery. Wrong credentials, truncation, failed authentication, or trailing data stop recovery.
- Preserves the raw inner header and XML bytes except literal XML 1.0 forbidden characters: U+0000–0008, U+000B, U+000C, U+000E–001F, U+FFFE, U+FFFF. This preserves history, attachments, protected ciphertext, unknown fields, whitespace, and line endings without translating the database into a new object model.
- Generates a fresh outer master seed and encryption IV. Keeps the same credentials, cipher, KDF settings, and compression setting. Authenticates and strictly checks the repaired database in memory and again from the encrypted temporary file before publishing it.
- Never overwrites an existing output, input, or key file. Only encrypted bytes are written to disk. Output permissions are owner-only on POSIX; Windows permissions follow the destination folder. Atomic publication requires a filesystem supporting hard links (such as APFS, NTFS, or ext4); use your computer's local disk, not a cloud/network or FAT/exFAT folder.
- Refuses non-UTF-8 XML, DTDs, unresolved structural XML errors, and unsupported format versions. It does not use a permissive XML recovery parser, fix arbitrary corruption, remove characters inside encrypted protected values, or recover the separate, unconfirmed long-notes report.
- KDBX 3.x, hardware/YubiKey challenge-response, and Windows-account credentials are not supported. The issue's writing bug affects KDBX 4; KeeForge reads KDBX 3.1 without writing it.
- Limits: 256 MiB input and decompressed payload, 1 MiB key file, Argon2 memory up to 1 GiB / 100 iterations / 16 lanes, AES-KDF up to 10 million rounds. Refuses unsupported or larger inputs instead of guessing.

Decrypted data necessarily exists in process memory during recovery. Python cannot guarantee erasure of those memory buffers; no decrypted temporary files or diagnostics containing field contents are created.

## Development and verification

```sh
python3 -m venv .venv
.venv/bin/python -m pip install '.[test]'
.venv/bin/pytest --cov=kdbx_recovery --cov-branch --cov-report=term-missing
.venv/bin/ruff check .
```

See [tests/fixtures/README.md](tests/fixtures/README.md) for synthetic fixture provenance. Tests exercise recovery and refusal, not just encryption round trips. They compare the raw payload byte-for-byte after only the documented character removal, reopen with ordinary PyKeePass, and independently check recovered files with KeePassXC when `KEEPASSXC_CLI` is set. CI runs on macOS, Windows, and Linux and requires KeePassXC interoperability on Linux.

Cryptography and KDBX envelope processing use [PyKeePass](https://github.com/libkeepass/pykeepass), pinned to 4.1.1.post1 because this tool uses its Construct adapters directly. The recovery layer does not implement its own ciphers or key derivation. See [SECURITY.md](SECURITY.md) for scope and reporting.

License: [GPL-3.0-only](LICENSE).
