"""Focused audit reproductions; assertions describe the required behavior."""
import pytest
from keri.app import habbing, configing


def open_persistent(root):
    return habbing.Habery(name="rmids-audit", temp=False, headDirPath=str(root),
                         cf=configing.Configer(name="rmids-audit", temp=True))


@pytest.mark.parametrize("empty", [False, True])
def test_group_roster(tmp_path, empty):
    hby = open_persistent(tmp_path)
    try:
        members = [hby.makeHab(name=f"m{i}") for i in range(3)]
        smids = [members[0].pre]
        rmids = [] if empty else [m.pre for m in members]
        group = hby.makeGroupHab(group="group", mhab=members[0], smids=smids,
                                 rmids=rmids, isith="1", nsith="0" if empty else "2")
        pre = group.pre
        assert len(group.kever.ndigers) == len(rmids)
        assert group.rmids == rmids, "constructor must preserve explicit empty roster"
        assert hby.db.rotationMembers(pre) == rmids
    finally:
        hby.close()
    hby = open_persistent(tmp_path)
    try:
        assert hby.db.rotationMembers(pre) == rmids
        assert len(hby.habs[pre].kever.ndigers) == len(rmids)
        assert hby.habs[pre].rmids == rmids, "reload must preserve stored rotation roster"
    finally:
        hby.close()
