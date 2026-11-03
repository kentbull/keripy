"""Collect explicit witness authorization codes for native command owners."""
from ...help import helping
from ...kering import ConfigurationError


def witnessAuths(wits, *, authenticate=False, codes=None, codeTime=None):
    """Return the existing witness-to-``code#timestamp`` header mapping.

    Codes use the same ``AID:code`` CLI convention as interact/rotate. Validate
    supplied options before prompting or authoring an event. Only selected
    witnesses may receive a code; no TOTP seed is accepted or retained here.
    """
    codes = codes if codes is not None else []
    if not authenticate:
        if codes or codeTime is not None:
            raise ConfigurationError('witness codes and code-time require --authenticate')
        return {}
    stamp = codeTime if codeTime is not None else helping.nowIso8601()
    try:
        if helping.fromIso8601(stamp).utcoffset() is None:
            raise ValueError('timezone is required')
    except (TypeError, ValueError) as error:
        raise ConfigurationError('witness code-time must be an ISO8601 timestamp with timezone') from error
    auths = {}
    for entry in codes:
        wit, separator, code = entry.partition(':')
        if (not separator or wit not in wits or wit in auths or not code
                or any(char in code for char in '#\r\n')):
            raise ConfigurationError('witness code must name one selected witness once as AID:code')
        auths[wit] = f'{code}#{stamp}'
    for wit in wits:
        if wit not in auths:
            code = input(f'Entire code for {wit}: ')
            if not code or any(char in code for char in '#\r\n'):
                raise ConfigurationError('invalid witness authentication code')
            auths[wit] = f'{code}#{helping.nowIso8601()}'
    return auths
