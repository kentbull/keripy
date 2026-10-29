"""Exact parse-only reply framing shared by live ESSR and archived evidence."""

from ..core import SerderKERI, messagize
from ..kering import Ilks, ValidationError


def parseReply(parser, stream, allowedRoutes):
    """Return one parsed reply with only explicit signature attachments.

    Parameters: parser is caller-owned; stream holds one complete reply frame;
        allowedRoutes is a collection of exact route strings.
    Returns: MsgParseDom retaining the original reply body and signatures.
    Raises: ValidationError on malformed, extra or unsupported material. This
        function neither verifies signature authority nor dispatches processors.
        The borrowed parser's genus version is restored even after failure.
    """
    if isinstance(allowedRoutes, (str, bytes)) or not allowedRoutes:
        raise ValidationError('Reply parsing requires explicit allowed routes')
    original = bytes(stream)
    remaining = bytearray(original)
    version = parser.version
    generator = parser.msgParsator(ims=remaining, framed=True, local=False)
    try:
        try:
            next(generator)
        except StopIteration as done:
            parsed = done.value
            frameVersion = parser.version
        else:
            raise ValidationError('Incomplete reply frame')
    except Exception:
        raise ValidationError('Invalid reply frame') from None
    finally:
        generator.close()
        parser.version = version
    if (remaining or not isinstance(parsed.serder, SerderKERI) or
            parsed.serder.ilk != Ilks.rpy or
            parsed.serder.route not in allowedRoutes or
            not parsed.serder.verify() or not (parsed.cigars or parsed.tsgs) or
            any(value for key, value in vars(parsed).items()
                if key not in ('serder', 'cigars', 'tsgs', 'local'))):
        raise ValidationError('Invalid reply body or attachments')
    # Parser may discard misplaced groups. Exact reconstruction prevents such
    # groups from hiding material outside the permitted signature attachments.
    if not any(original == messagize(parsed.serder, cigars=parsed.cigars,
                                      tsgs=parsed.tsgs, framed=framed,
                                      gvrsn=frameVersion)
               for framed in (True, False)):
        raise ValidationError('Noncanonical reply frame')
    return parsed
