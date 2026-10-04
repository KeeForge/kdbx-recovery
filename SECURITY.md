# Security and recovery scope

This tool removes literal XML-invalid characters from authenticated KDBX 4 payloads. It is not password cracking software or a general corruption repair utility. Header and block authentication must succeed before any XML recovery takes place. No network access is used during recovery.

The tool preserves the raw XML representation instead of serializing through PyKeePass's entry model. This is deliberate: normal model parsers can normalize line endings, filter decrypted protected values, or omit unknown data. Fresh outer encryption randomness is generated while the unchanged inner stream key keeps existing protected ciphertext readable.

Do not weaken authentication, enable `recover=True` in the XML parser, overwrite inputs, or add password arguments. Keep errors independent of decrypted field contents. Tests must include tampered headers, payload blocks and the terminal HMAC, wrong credentials, output races, and exact payload preservation. Review the adapter graph when updating the pinned dependency.

Files are held in memory, with explicit input/decompression/KDF limits. Decrypted Python buffers cannot be reliably zeroed. OS swap, crash dumps, filesystem snapshots, and a compromised computer are outside the tool's guarantees. Use an account and computer you trust.

Please report vulnerabilities privately through [GitHub private vulnerability reporting](https://github.com/KeeForge/kdbx-recovery/security/advisories/new). Use synthetic databases and never send real passwords or personal databases.
