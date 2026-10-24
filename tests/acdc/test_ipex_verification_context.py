"""Concrete native semantic contexts must retain their actual evidence owners."""
import pytest

from keri import Vrsn_2_0
from keri.acdc import Regery
from keri.acdc.ipexing import IpexHandler, NativeVerification
from keri.app import ipexing as dispatching, openHby
from keri.kering import ConfigurationError


@pytest.mark.parametrize('handlerType', [IpexHandler, dispatching.IpexHandler])
@pytest.mark.parametrize('invalidContext', ['habery', 'regery', True, False])
def test_ipex_handler_rejects_context_with_wrong_type_or_evidence_owner(handlerType, invalidContext):
    """Reject miscomposition through ConfigurationError before processing evidence.

    Args:
        handlerType: Native processor or version dispatcher constructor.
        invalidContext: Wrong Habery/Regery binding or a boolean acceptance claim.

    Returns:
        None. Assertions prove matching concrete contexts work and every invalid
        composition raises the documented ConfigurationError, never NameError.
    """
    with (openHby(name='context-owner', version=Vrsn_2_0) as owner,
          openHby(name='context-foreign', version=Vrsn_2_0) as foreign):
        rgy = Regery(hby=owner, name=owner.name, temp=True)
        other = Regery(hby=foreign, name=foreign.name, temp=True)
        try:
            shared = NativeVerification(owner, rgy)
            handler = handlerType('/ipex/grant', owner, None, rgy=rgy, verification=shared)
            native = handler.native if handlerType is dispatching.IpexHandler else handler
            assert native.verification is shared
            if invalidContext == 'habery':
                context = NativeVerification(foreign, rgy)
            elif invalidContext == 'regery':
                context = NativeVerification(owner, other)
            else:
                context = invalidContext
            with pytest.raises(ConfigurationError, match='context must belong to this Habery and Regery'):
                handlerType('/ipex/grant', owner, None, rgy=rgy, verification=context)
        finally:
            other.close()
            rgy.close()
