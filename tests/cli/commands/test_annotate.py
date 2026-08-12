# -*- coding: utf-8 -*-
"""
tests.cli.commands.test_annotate module
"""
import io
import subprocess
import sys

import multicommand

from keri.cli import commands


NATIVE = (
    b'-FA50OKERICAACAAXicpEFaYE2LTv8dItUgQzIHKRA9FaHDrHtIHNs-m5DJKWXRNDNG2arBDtH'
    b'K_JyHRAq-emRdC6UM-yIpCAeJIWDiXp4HxMAAAMAAB-JALDNG2arBDtHK_JyHRAq-emRdC6UM-yI'
    b'pCAeJIWDiXp4HxMAAB-JALEFXIx7URwmw7AVQTBcMxPXfOOJ2YYA1SJAam69DXV8D2MAAA-JAA'
    b'-JAA-JAA')
JSON_RPY = b'{"v":"KERI10JSON00002e_","t":"rpy","d":"Eabc"}'


class FakeStdin:
    """Binary stdin wrapper for argparse handler tests."""

    def __init__(self, data):
        self.buffer = io.BytesIO(data)


def test_annotate_stdin_stdout(monkeypatch, capsys):
    parser = multicommand.create_parser(commands)
    monkeypatch.setattr(sys, "stdin", FakeStdin(NATIVE))

    args = parser.parse_args(["annotate"])
    assert args.handler is not None
    doers = args.handler(args)

    assert doers == []
    output = capsys.readouterr().out
    assert "FixBodyGroup" in output
    assert "Blake3_256" in output


def test_annotate_file_stdout(tmp_path, capsys):
    parser = multicommand.create_parser(commands)
    inpath = tmp_path / "in.cesr"
    inpath.write_bytes(NATIVE)

    args = parser.parse_args(["annotate", "--in", str(inpath)])
    assert args.handler is not None
    doers = args.handler(args)

    assert doers == []
    output = capsys.readouterr().out
    assert "FixBodyGroup" in output
    assert "Blake3_256" in output


def test_annotate_file_out(tmp_path, capsys):
    parser = multicommand.create_parser(commands)
    inpath = tmp_path / "in.cesr"
    outpath = tmp_path / "out.annotated"
    inpath.write_bytes(NATIVE)

    args = parser.parse_args(["annotate", "--in", str(inpath), "--out",
                              str(outpath)])
    assert args.handler is not None
    doers = args.handler(args)

    assert doers == []
    assert capsys.readouterr().out == ""
    output = outpath.read_text(encoding="utf-8")
    assert "FixBodyGroup" in output
    assert "Blake3_256" in output


def test_annotate_colored_stdout(monkeypatch, capsys):
    parser = multicommand.create_parser(commands)
    monkeypatch.setattr(sys, "stdin", FakeStdin(NATIVE))

    args = parser.parse_args(["annotate", "--colored"])
    assert args.handler is not None
    doers = args.handler(args)

    assert doers == []
    output = capsys.readouterr().out
    assert "\x1b[" in output
    assert "FixBodyGroup" in output


def test_annotate_colored_pretty_json_stdout(tmp_path, capsys):
    parser = multicommand.create_parser(commands)
    inpath = tmp_path / "in.cesr"
    inpath.write_bytes(JSON_RPY)

    args = parser.parse_args(["annotate", "--in", str(inpath), "--colored",
                              "--pretty"])
    assert args.handler is not None
    doers = args.handler(args)

    assert doers == []
    output = capsys.readouterr().out
    assert '\x1b[94m"v"\x1b[0m' in output
    assert '\x1b[32m"KERI10JSON00002e_"\x1b[0m' in output
    assert "\x1b[90mSERDER KERI JSON ilk=rpy " in output


def test_annotate_colored_file_out_is_plain(tmp_path, capsys):
    parser = multicommand.create_parser(commands)
    inpath = tmp_path / "in.cesr"
    outpath = tmp_path / "out.annotated"
    inpath.write_bytes(JSON_RPY)

    args = parser.parse_args(["annotate", "--in", str(inpath), "--out",
                              str(outpath), "--colored", "--pretty"])
    assert args.handler is not None
    doers = args.handler(args)

    assert doers == []
    assert capsys.readouterr().out == ""
    output = outpath.read_text(encoding="utf-8")
    assert "\x1b[" not in output
    assert "SERDER KERI JSON" in output


def test_annotate_module_reads_piped_stdin():
    """Test the top-level CLI command reads stdin by default."""
    result = subprocess.run(
        [sys.executable, "-m", "keri.cli.kli", "annotate"],
        input=NATIVE,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0
    assert b"FixBodyGroup" in result.stdout
    assert b"Blake3_256" in result.stdout
