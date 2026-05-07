# -*- coding: utf-8 -*-
"""
tests.cli.commands.test_deannotate module
"""
import io
import subprocess
import sys

import multicommand

from keri.cli import commands
from keri.core.annotating import Annotator, annot


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


def test_deannotate_stdin_stdout(monkeypatch, capsysbinary):
    parser = multicommand.create_parser(commands)
    monkeypatch.setattr(sys, "stdin", FakeStdin(annot(bytearray(NATIVE)).encode()))

    args = parser.parse_args(["deannotate"])
    assert args.handler is not None
    doers = args.handler(args)

    assert doers == []
    assert capsysbinary.readouterr().out == NATIVE


def test_deannotate_file_out_exact_bytes(tmp_path, capsysbinary):
    parser = multicommand.create_parser(commands)
    inpath = tmp_path / "in.annotated"
    outpath = tmp_path / "out.cesr"
    inpath.write_text(annot(bytearray(JSON_RPY), pretty=True), encoding="utf-8")

    args = parser.parse_args(["deannotate", "--in", str(inpath), "--out",
                              str(outpath)])
    assert args.handler is not None
    doers = args.handler(args)

    assert doers == []
    assert capsysbinary.readouterr().out == b""
    assert outpath.read_bytes() == JSON_RPY


def test_deannotate_module_restores_pretty_annotation():
    annotated = subprocess.run(
        [sys.executable, "-m", "keri.cli.kli", "annotate", "--pretty"],
        input=JSON_RPY,
        capture_output=True,
        check=True,
    )
    result = subprocess.run(
        [sys.executable, "-m", "keri.cli.kli", "deannotate"],
        input=annotated.stdout,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0
    assert result.stdout == JSON_RPY


def test_deannotate_does_not_strip_colorized_annotations(monkeypatch,
                                                         capsysbinary):
    parser = multicommand.create_parser(commands)
    colored = Annotator().annotate(bytearray(JSON_RPY), colored=True)
    monkeypatch.setattr(sys, "stdin", FakeStdin(colored.encode()))

    args = parser.parse_args(["deannotate"])
    assert args.handler is not None
    doers = args.handler(args)

    assert doers == []
    output = capsysbinary.readouterr().out
    assert b"\x1b[" in output
    assert output != JSON_RPY
