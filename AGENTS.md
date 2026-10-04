# Repository guidance

This is a narrow offline recovery tool for KeeForge issue #181. Keep source files in `src/kdbx_recovery`, regression tests and synthetic fixtures in `tests`. Do not broaden recovery silently or reconstruct the database through an entry model. Read SECURITY.md before changing recovery.

Use the existing pinned PyKeePass envelope adapters for crypto and KDBX authentication. Authenticate before recovery, preserve all untouched payload bytes, and never overwrite input or existing output. Never commit personal databases, credentials, decrypted exports, or scratch artifacts. Temporary agent artifacts belong in `/Users/tan/src/KeeForge/scratch/` on the maintainer's Mac.

Run `pytest --cov=kdbx_recovery --cov-branch` and `ruff check .`. KeePassXC integration must pass for behavior changes (`KEEPASSXC_CLI=/path/to/keepassxc-cli pytest`). Keep all commits DCO signed off (`git commit -s`).
