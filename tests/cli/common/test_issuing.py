# -*- encoding: utf-8 -*-
"""
tests.cli.common.test_issuing module

"""
import os
from types import SimpleNamespace

from keri.cli.common.issuing import IpexV2Issuance


def test_record_publishes_initial_output_atomically(tmp_path, monkeypatch):
    """The output file never exists with partial content: the first record is
    written beside it and renamed into place, later records append."""
    output = tmp_path / "evidence.cesr"
    command = SimpleNamespace(args=SimpleNamespace(output=str(output)))
    seen = {}

    real_replace = os.replace

    def replace(src, dst):
        seen["final_absent_before_replace"] = not os.path.exists(dst)
        seen["part_content"] = open(src, "rb").read()
        real_replace(src, dst)

    monkeypatch.setattr("keri.cli.common.issuing.os.replace", replace)

    IpexV2Issuance.record(command, b"first", initial=True)
    assert seen == dict(final_absent_before_replace=True, part_content=b"first")
    assert output.read_bytes() == b"first"
    assert not list(tmp_path.glob("*.part"))

    IpexV2Issuance.record(command, b"second")
    assert output.read_bytes() == b"firstsecond"

    command.args.output = None
    IpexV2Issuance.record(command, b"ignored", initial=True)
    assert output.read_bytes() == b"firstsecond"
