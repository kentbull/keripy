"""Apply pytest's persistent-store root before a real child CLI starts."""
import os


try:
    root = os.environ["KERIPY_TEST_STORE_ROOT"]
    if not os.path.isabs(root) or not os.path.isdir(root):
        raise ValueError("KERIPY_TEST_STORE_ROOT must be an existing absolute directory")

    from keri.db.dbing import LMDBer
    from keri.app.configing import Configer

    for cls in (LMDBer, Configer):
        cls.HeadDirPath = root
        cls.AltHeadDirPath = root
except Exception as ex:
    # Python prints and ignores ordinary sitecustomize exceptions. Isolation
    # failure must instead stop startup before a child opens a production root.
    raise SystemExit(f"Unable to isolate pytest KERI stores: {ex}") from ex
