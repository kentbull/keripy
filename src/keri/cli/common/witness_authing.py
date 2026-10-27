"""Read explicit short-lived witness authorization values for operator commands."""
import json
from pathlib import Path

from keri.kering import ConfigurationError


def readWitnessAuth(path):
    """Return an explicit witness-AID to authorization-header map from JSON.

    Parameters:
        path: operator-selected file, or None for ordinary unauthenticated
            witness transport. Values contain existing ``code#timestamp`` data.
    Returns:
        dict[str, str]: a new map passed to the existing Receiptor API.
    Raises:
        ConfigurationError: the file is not a map of nonempty string values.
        OSError, ValueError: the file cannot be read or decoded as JSON.

    This adapter stores no TOTP seeds, derives no codes and changes no witness
    policy. Providers/operators generate short-lived values; the witness remains
    responsible for authenticating them. The CLI never prints their contents.
    """
    if path is None:
        return {}
    data = json.loads(Path(path).read_text())
    if not isinstance(data, dict) or any(not isinstance(key, str) or not key
            or not isinstance(value, str) or not value for key, value in data.items()):
        raise ConfigurationError('witness authorization must map AIDs to nonempty header strings')
    return data
