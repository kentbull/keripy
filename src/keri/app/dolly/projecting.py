"""Project only authorized, actually disclosed values from one accepted grant."""
from collections.abc import Mapping

from keri.core import Diger
from keri.kering import ValidationError


def project(credential, fields, required=()):
    """Return a business view and explicit disclosure facts, never an ACDC.

    ``fields`` maps output names to slash-separated credential paths. A digest
    encountered before the path ends denotes an undisclosed committed block.
    A scalar at the selected leaf is a disclosed value, including a real null.
    Missing properties stay distinct from undisclosed committed properties.
    """
    values, disclosure = {}, {}
    for name, path in fields.items():
        parts = path.split('/')
        if not name or not parts or any(not part for part in parts):
            raise ValidationError('projection requires explicit nonempty field paths')
        value, state = credential.sad, 'disclosed'
        for part in parts:
            if isinstance(value, str):
                try:
                    Diger(qb64=value)
                    state = 'undisclosed'
                except Exception:
                    state = 'invalid'
                break
            if not isinstance(value, Mapping):
                state = 'invalid'
                break
            if part not in value:
                state = 'absent'
                break
            value = value[part]
        if state == 'disclosed':
            # Do not recursively copy a block containing unselected data or salts.
            if isinstance(value, (Mapping, list)):
                state = 'invalid'
            elif value is None:
                state = 'disclosed_null'
        values[name] = value if state in ('disclosed', 'disclosed_null') else None
        disclosure[name] = state
    if any(disclosure.get(name) not in ('disclosed', 'disclosed_null') for name in required):
        raise ValidationError('required business fields were not disclosed')
    if 'invalid' in disclosure.values():
        raise ValidationError('business projection has an invalid disclosed shape')
    return values, disclosure
