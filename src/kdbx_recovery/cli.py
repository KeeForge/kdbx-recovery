import argparse
import getpass
import sys
from pathlib import Path

from . import __version__
from .container import RecoveryError
from .recovery import recover_file


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Recover XML-invalid characters from a KDBX 4 database, entirely offline."
    )
    parser.add_argument("--version", action="version", version=f"kdbx-recover {__version__}")
    parser.add_argument("database", type=Path, help="damaged KDBX file (never modified)")
    destination = parser.add_mutually_exclusive_group(required=True)
    destination.add_argument("--output", type=Path, help="new recovered KDBX file")
    destination.add_argument("--check", action="store_true", help="report removals without writing")
    parser.add_argument("--keyfile", type=Path, help="existing database key file, if required")
    parser.add_argument(
        "--keyfile-only", action="store_true", help="database has no password component"
    )
    parser.add_argument(
        "--password-stdin", action="store_true", help="read one password line from standard input"
    )
    args = parser.parse_args(argv)
    if args.keyfile_only and (args.keyfile is None or args.password_stdin):
        parser.error("--keyfile-only requires --keyfile and cannot use --password-stdin")
    try:
        if args.keyfile_only:
            password = None
        elif args.password_stdin:
            line = sys.stdin.readline()
            if not line:
                raise RecoveryError("No password was supplied on standard input.")
            password = line.removesuffix("\n").removesuffix("\r")
        else:
            if not sys.stdin.isatty():
                raise RecoveryError(
                    "Use a terminal for the hidden password prompt or --password-stdin."
                )
            password = getpass.getpass("Database password: ")
        result = recover_file(args.database, args.output, password, args.keyfile)
        if not result.removed:
            print("No XML-invalid characters found. No output was written.")
        else:
            print("Characters to remove:" if args.check else "Characters removed:")
            for scalar, count in result.removed.items():
                print(f"  U+{scalar:04X}: {count}")
            if args.check:
                print("Check complete. No files were changed.")
            else:
                print(f"Recovered database verified and saved to: {args.output}")
                print("Open it in KeeForge or KeePassXC and check your entries before using it.")
        return 0
    except RecoveryError as error:
        print(f"Recovery stopped: {error}", file=sys.stderr)
        return 1
    except OSError:
        print(
            "Recovery stopped: could not read or publish the file. Check permissions, free space, "
            "and that the output is new. The output folder must support hard links.",
            file=sys.stderr,
        )
        return 1
    except (KeyboardInterrupt, EOFError):
        print("Recovery cancelled.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
