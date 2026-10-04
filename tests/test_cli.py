import io
import subprocess
import sys

import pytest

from kdbx_recovery import cli

from .conftest import PASSWORD
from .test_recovery import inject


def invoke(monkeypatch, argv, password=PASSWORD):
    monkeypatch.setattr(sys, "stdin", io.StringIO(password + "\n"))
    return cli.main([*argv, "--password-stdin"])


def test_cli_output_and_check(make_database, tmp_path, monkeypatch, capsys):
    data, _ = make_database(inject)
    source, output = tmp_path / "damaged", tmp_path / "recovered"
    source.write_bytes(data)
    assert invoke(monkeypatch, [str(source), "--check"]) == 0
    captured = capsys.readouterr()
    assert "U+0000: 1" in captured.out
    assert "No files were changed" in captured.out
    assert not output.exists()
    assert invoke(monkeypatch, [str(source), "--output", str(output)]) == 0
    captured = capsys.readouterr()
    assert "verified and saved" in captured.out
    assert PASSWORD not in captured.out + captured.err
    assert "custom-secret" not in captured.out + captured.err
    assert output.exists()


def test_cli_healthy_and_wrong_password(make_database, tmp_path, monkeypatch, capsys):
    data, _ = make_database()
    source = tmp_path / "healthy"
    source.write_bytes(data)
    assert invoke(monkeypatch, [str(source), "--check"]) == 0
    assert "No XML-invalid" in capsys.readouterr().out
    assert invoke(monkeypatch, [str(source), "--check"], "wrong") == 1
    output = capsys.readouterr()
    assert "authenticate" in output.err
    assert PASSWORD not in output.err + output.out


def test_password_prompt_and_nonterminal(make_database, tmp_path, monkeypatch, capsys):
    data, _ = make_database(inject)
    source = tmp_path / "database"
    source.write_bytes(data)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    prompts = []

    def prompt(text):
        prompts.append(text)
        return PASSWORD

    monkeypatch.setattr(cli.getpass, "getpass", prompt)
    assert cli.main([str(source), "--check"]) == 0
    assert prompts == ["Database password: "]
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    assert cli.main([str(source), "--check"]) == 1
    assert "terminal" in capsys.readouterr().err


def test_keyfile_only_and_empty_password(make_database, tmp_path, monkeypatch):
    key = tmp_path / "key"
    key.write_bytes(b"k" * 32)
    source = tmp_path / "database"
    data, _ = make_database(inject, keyfile=key.read_bytes(), password=None)
    source.write_bytes(data)
    assert cli.main([str(source), "--check", "--keyfile", str(key), "--keyfile-only"]) == 0
    data, _ = make_database(inject, keyfile=key.read_bytes(), password="")
    source.write_bytes(data)
    assert invoke(monkeypatch, [str(source), "--check", "--keyfile", str(key)], "") == 0


@pytest.mark.parametrize(
    "options",
    [
        [],
        ["--keyfile-only"],
        ["--keyfile", "key", "--keyfile-only", "--password-stdin"],
        ["--output", "o", "--check"],
    ],
)
def test_invalid_arguments(options):
    with pytest.raises(SystemExit) as error:
        cli.main(["database", *([] if not options else ["--check"]), *options])
    assert error.value.code == 2


def test_empty_stdin_and_io_failure(monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    assert cli.main(["missing", "--check", "--password-stdin"]) == 1
    assert "No password" in capsys.readouterr().err
    assert invoke(monkeypatch, ["missing", "--check"]) == 1
    assert "permissions" in capsys.readouterr().err


@pytest.mark.parametrize("exception", [KeyboardInterrupt, EOFError])
def test_cancellation(monkeypatch, exception):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)

    def cancel(*args):
        raise exception

    monkeypatch.setattr(cli.getpass, "getpass", cancel)
    assert cli.main(["database", "--check"]) == 130


def test_subprocess_entrypoint(make_database, tmp_path):
    data, _ = make_database(inject)
    source, output = tmp_path / "damaged.kdbx", tmp_path / "recovered.kdbx"
    source.write_bytes(data)
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "kdbx_recovery.cli",
            str(source),
            "--output",
            str(output),
            "--password-stdin",
        ],
        input=PASSWORD + "\n",
        text=True,
        capture_output=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert output.exists()
    assert PASSWORD not in result.stdout + result.stderr
    help_result = subprocess.run(
        [sys.executable, "-m", "kdbx_recovery.cli", "--help"], text=True, capture_output=True
    )
    assert help_result.returncode == 0
    assert "--password-stdin" in help_result.stdout
    assert "--password " not in help_result.stdout
