# -*- encoding: utf-8 -*-
"""
keri.app.tocking module

Centralized tock configuration for doer timing control (HIO scheduler tocks).
Environment variables allow production tuning without code changes.

Tock values control how frequently doer methods execute:
- 0.0 = run on the next scheduler cycle (one ``doist`` tick, 10 ms by default)
- 1.0 = run once per second
- Higher values = less frequent execution, lower CPU usage

Defaults keep active message, cue, queue, and network-progress paths on the
next Doist cycle by using the lowest possible value, 0.0. So do waits for local
state that another doer in the same process sets (receipt messengers going
idle, CLI commands waiting on a database row): their cost is one cheap check
per tick. Positive, non-zero defaults are reserved for full escrow scans and
waits that touch a remote host (failure backoff, reconnect, OOBI retry).

The defaults were measured on the v2 stack (macOS, Python 3.14, hio 0.7.20,
``kli witness demo`` with six witnesses in one process plus witnessed kli
commands): see the comment on each value. Every tock is quantized to the
``doist`` tick, so the tick sets both the latency floor and the idle CPU cost.

These tocks cover operator-meaningful
 - inbound processing (HTTP/TCP receives)
 - outbound dispatch (HTTP/TCP client sends)
 - workflow coordination (other DoDoer coordination)
 - deferred-state scans (escrows)
 - maintenance and backoff
"""

import math
import os
from collections.abc import Mapping
from dataclasses import dataclass

from .. import kering

@dataclass(frozen=True)
class Tock:
    """Environment variable and default for one scheduler cadence."""

    env: str
    default: float = 0.0


@dataclass(frozen=True)
class TockAlias:
    """Describe one coarse tock group setting and its config targets."""

    env: str
    targets: tuple[str, ...]

# Default tock values mapped by config prop name to Tock env key and default
TOCKS: dict[str, Tock] = {}

# Shared default for every escrow scan (host and workflow escrows). Measured at
# a 5 ms tick: scanning host escrows every cycle cost the six-witness demo 19.4 %
# of a core idle, every 0.1 s 16.8 %, every 1.0 s 14.3 %. 0.1 s keeps most of
# that saving while bounding escrowed-event latency at 0.1 s instead of the
# 0.5 s workflow and 1.0 s host defaults this replaced.
ESCROW_TOCK = 0.1

# tock subkeys cascading tock to "targets" subkeys, if present
TOCK_ALIASES: dict[str, TockAlias] = {}

# Witness component tocks (indirecting.py - WitnessStart)
KERI_WITNESS_MSG_TOCK_KEY = "KERI_WITNESS_MSG_TOCK"
KERI_WITNESS_ESCROW_TOCK_KEY = "KERI_WITNESS_ESCROW_TOCK"
KERI_WITNESS_CUE_TOCK_KEY = "KERI_WITNESS_CUE_TOCK"

TOCKS["witnessMsg"] = Tock(KERI_WITNESS_MSG_TOCK_KEY, 0.0)
TOCKS["witnessEscrow"] = Tock(KERI_WITNESS_ESCROW_TOCK_KEY, ESCROW_TOCK)
TOCKS["witnessCue"] = Tock(KERI_WITNESS_CUE_TOCK_KEY, 0.0)

# Indirector component tocks (indirecting.py - Indirector)
KERI_INDIRECTOR_MSG_TOCK_KEY = "KERI_INDIRECTOR_MSG_TOCK"
KERI_INDIRECTOR_CUE_TOCK_KEY = "KERI_INDIRECTOR_CUE_TOCK"
KERI_INDIRECTOR_ESCROW_TOCK_KEY = "KERI_INDIRECTOR_ESCROW_TOCK"

TOCKS["indirectorMsg"] = Tock(KERI_INDIRECTOR_MSG_TOCK_KEY, 0.0)
TOCKS["indirectorCue"] = Tock(KERI_INDIRECTOR_CUE_TOCK_KEY, 0.0)
TOCKS["indirectorEscrow"] = Tock(KERI_INDIRECTOR_ESCROW_TOCK_KEY, ESCROW_TOCK)

# MailboxDirector component tocks (indirecting.py - MailboxDirector)
KERI_MAILBOX_POLL_TOCK_KEY = "KERI_MAILBOX_POLL_TOCK"
KERI_MAILBOX_MSG_TOCK_KEY = "KERI_MAILBOX_MSG_TOCK"
KERI_MAILBOX_ESCROW_TOCK_KEY = "KERI_MAILBOX_ESCROW_TOCK"

TOCKS["mailboxPoll"] = Tock(KERI_MAILBOX_POLL_TOCK_KEY, 0.0)
TOCKS["mailboxMsg"] = Tock(KERI_MAILBOX_MSG_TOCK_KEY, 0.0)
TOCKS["mailboxEscrow"] = Tock(KERI_MAILBOX_ESCROW_TOCK_KEY, ESCROW_TOCK)

# Poller component tocks (indirecting.py - Poller)
KERI_POLLER_EVENT_TOCK_KEY = "KERI_POLLER_EVENT_TOCK"
KERI_POLLER_CONNECT_TOCK_KEY = "KERI_POLLER_CONNECT_TOCK"

TOCKS["pollerEvent"] = Tock(KERI_POLLER_EVENT_TOCK_KEY, 0.0)
# 0.5 s: backoff while the witness has no usable endpoint; it only limits retries and logging
TOCKS["pollerConnect"] = Tock(KERI_POLLER_CONNECT_TOCK_KEY, 0.5)

# Poller reconnect wait after a mailbox long-poll window closes (indirecting.py - Poller)
KERI_POLLER_RETRY_TOCK_KEY = "KERI_POLLER_RETRY_TOCK"

# 0.5 s: one reconnect per 30 s window per poller; the 5 s server SSE hint it replaces left
# messages queued up to 5 s each window, while 0.5 s adds no meaningful load on the witness
TOCKS["pollerRetry"] = Tock(KERI_POLLER_RETRY_TOCK_KEY, 0.5)

# ReceiptEnd component tocks (indirecting.py - ReceiptEnd)
KERI_RECEIPT_INTERCEPT_TOCK_KEY = "KERI_RECEIPT_INTERCEPT_TOCK"

TOCKS["receiptIntercept"] = Tock(KERI_RECEIPT_INTERCEPT_TOCK_KEY, 0.0)

# Reactor component tocks (directing.py - Reactor)
KERI_REACTOR_MSG_TOCK_KEY = "KERI_REACTOR_MSG_TOCK"
KERI_REACTOR_CUE_TOCK_KEY = "KERI_REACTOR_CUE_TOCK"
KERI_REACTOR_ESCROW_TOCK_KEY = "KERI_REACTOR_ESCROW_TOCK"

TOCKS["reactorMsg"] = Tock(KERI_REACTOR_MSG_TOCK_KEY, 0.0)
TOCKS["reactorCue"] = Tock(KERI_REACTOR_CUE_TOCK_KEY, 0.0)
TOCKS["reactorEscrow"] = Tock(KERI_REACTOR_ESCROW_TOCK_KEY, ESCROW_TOCK)

# Reactant component tocks (directing.py - Reactant)
KERI_REACTANT_MSG_TOCK_KEY = "KERI_REACTANT_MSG_TOCK"
KERI_REACTANT_CUE_TOCK_KEY = "KERI_REACTANT_CUE_TOCK"
KERI_REACTANT_ESCROW_TOCK_KEY = "KERI_REACTANT_ESCROW_TOCK"

TOCKS["reactantMsg"] = Tock(KERI_REACTANT_MSG_TOCK_KEY, 0.0)
TOCKS["reactantCue"] = Tock(KERI_REACTANT_CUE_TOCK_KEY, 0.0)
TOCKS["reactantEscrow"] = Tock(KERI_REACTANT_ESCROW_TOCK_KEY, ESCROW_TOCK)

# Respondant component tocks (storing.py - Respondant)
KERI_RESPONDANT_CUE_TOCK_KEY = "KERI_RESPONDANT_CUE_TOCK"

TOCKS["respondant"] = Tock(KERI_RESPONDANT_CUE_TOCK_KEY, 0.0)

# Receiptor component tocks (agenting.py - Receiptor)
KERI_RECEIPTOR_TOCK_KEY = "KERI_RECEIPTOR_TOCK"

TOCKS["receiptor"] = Tock(KERI_RECEIPTOR_TOCK_KEY, 0.0)

# OOBI resolution and authentication (oobiing.py)
KERI_OOBI_TOCK_KEY = "KERI_OOBI_TOCK"

TOCKS["oobi"] = Tock(KERI_OOBI_TOCK_KEY, 0.0)

# Delay before a failed OOBI resolution is retried (oobiing.py - Oobiery)
KERI_OOBI_RETRY_TOCK_KEY = "KERI_OOBI_RETRY_TOCK"

# 5 s: a failed OOBI is a remote host that refused or failed; retry it at most every 5 s,
# not every tick, but do not leave a transient failure blocking a command for 30 s
TOCKS["oobiRetry"] = Tock(KERI_OOBI_RETRY_TOCK_KEY, 5.0)

# WitnessReceiptor component tocks (agenting.py)
KERI_WITNESS_RECEIPTOR_TOCK_KEY = "KERI_WITNESS_RECEIPTOR_TOCK"
KERI_WITNESS_RECEIPTOR_IDLE_TOCK_KEY = "KERI_WITNESS_RECEIPTOR_IDLE_TOCK"

TOCKS["witnessReceiptor"] = Tock(KERI_WITNESS_RECEIPTOR_TOCK_KEY, 0.0)
# 0.0: waits for local messengers to go idle; the former 1.0 s wait added about 0.9 s to
# every witnessed incept, rotate and interact (incept 2.6 s -> 1.7 s at a 10 ms tick)
TOCKS["witnessReceiptorIdle"] = Tock(KERI_WITNESS_RECEIPTOR_IDLE_TOCK_KEY, 0.0)

# WitnessInquisitor component tocks (agenting.py)
KERI_WITNESS_INQUISITOR_TOCK_KEY = "KERI_WITNESS_INQUISITOR_TOCK"

TOCKS["witnessInquisitor"] = Tock(KERI_WITNESS_INQUISITOR_TOCK_KEY, 0.0)

# WitnessPublisher component tocks (agenting.py)
KERI_WITNESS_PUBLISHER_TOCK_KEY = "KERI_WITNESS_PUBLISHER_TOCK"

TOCKS["witnessPublisher"] = Tock(KERI_WITNESS_PUBLISHER_TOCK_KEY, 0.0)

# Registrar and Credentialer tocks, and prior VDR group alias (credentialing.py)
KERI_VDR_ESCROW_TOCK_KEY = "KERI_VDR_ESCROW_TOCK"
TOCK_ALIASES["vdrEscrow"] = TockAlias(
    env=KERI_VDR_ESCROW_TOCK_KEY,
    targets=("registrarEscrow", "credentialerEscrow"),
)

KERI_REGISTRAR_ESCROW_TOCK_KEY = "KERI_REGISTRAR_ESCROW_TOCK"
KERI_CREDENTIALER_ESCROW_TOCK_KEY = "KERI_CREDENTIALER_ESCROW_TOCK"

TOCKS["registrarEscrow"] = Tock(KERI_REGISTRAR_ESCROW_TOCK_KEY, ESCROW_TOCK)
TOCKS["credentialerEscrow"] = Tock(KERI_CREDENTIALER_ESCROW_TOCK_KEY, ESCROW_TOCK)

# Counselor component tocks (grouping.py)
KERI_COUNSELOR_ESCROW_TOCK_KEY = "KERI_COUNSELOR_ESCROW_TOCK"

TOCKS["counselorEscrow"] = Tock(KERI_COUNSELOR_ESCROW_TOCK_KEY, ESCROW_TOCK)

# Delegation escrow processing (delegating.py - Anchorer)
KERI_ANCHORER_ESCROW_TOCK_KEY = "KERI_ANCHORER_ESCROW_TOCK"

TOCKS["anchorerEscrow"] = Tock(KERI_ANCHORER_ESCROW_TOCK_KEY, ESCROW_TOCK)

# Process Doist tick (directing.py - runController); every other tock is
# quantized to this tick. Must be positive: at 0.0 hio's Doist tyme never
# advances, so any positive wait never ends. Measured knee at 10 ms: from
# 31.25 ms to 10 ms witnessed commands gained 0.2-0.5 s each (interact 1.75 s ->
# 1.29 s); 5 ms and 2 ms gained nothing further. Idle cost roughly doubles per
# halving: six-witness demo 3-4 % of a core at 31.25 ms, 10 % at 10 ms, 14-19 %
# at 5 ms, 28-30 % at 2 ms, 50 % at 1 ms; an idle kli mailbox poller 1.3 % at
# 31.25 ms, 3.5 % at 10 ms, 6 % at 5 ms, 12-14 % at 2 ms.
KERI_DOIST_TOCK_KEY = "KERI_DOIST_TOCK"

TOCKS["doist"] = Tock(KERI_DOIST_TOCK_KEY, 0.01)

# CLI command waits for local state another doer in the same process sets
# (cli/commands: init, oobi resolve, contacts add/query, query, challenge
# verify, multisig continue)
KERI_COMMAND_POLL_TOCK_KEY = "KERI_COMMAND_POLL_TOCK"

# 0.0: one local database read per tick; the former 0.25-2.0 s waits added up to
# their full length per command (challenge verify 2.9 s -> 1.0 s)
TOCKS["commandPoll"] = Tock(KERI_COMMAND_POLL_TOCK_KEY, 0.0)

def _validateTock(value, source):
    """Return a finite, non-negative float or raise ConfigurationError."""

    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise kering.ConfigurationError(f"Invalid tock for {source}: {value!r}")

    value = float(value)
    if not math.isfinite(value) or value < 0.0:
        raise kering.ConfigurationError(f"Invalid tock for {source}: {value!r}")

    return value


def _parseEnvTock(value, source):
    """Parse and validate an environment-variable tock."""

    if not isinstance(value, str) or not value.strip():
        raise kering.ConfigurationError(f"Invalid tock for {source}: {value!r}")

    try:
        value = float(value)
    except ValueError as ex:
        raise kering.ConfigurationError(
            f"Invalid tock for {source}: {value!r}"
        ) from ex

    return _validateTock(value, source)


def resolveTocks(cfTocks=None, *, tocks=TOCKS,
                 aliases=TOCK_ALIASES, environ=None, reserved=("signify",)):
    """
    Resolve and validate one scheduler configuration dictionary using the following precedence
    rule: specific env > coarse env > specific config > coarse config > default.

    Parameters:
        cfTocks (dict): supplied configured tocks
        tocks (dict): default tock configuration
        aliases (dict): configuration target aliases (coarse grained tock definitions)
        environ (dict): environment variables; defaulted from OS
        reserved (list): reserved tock config subsections such as for Signify/KERIA tocks
    """

    cfTocks = {} if cfTocks is None else cfTocks
    if not isinstance(cfTocks, Mapping):
        raise kering.ConfigurationError(
            f"Invalid tocks configuration: expected mapping, got {type(cfTocks).__name__}"
        )

    environ = os.environ if environ is None else environ
    if not isinstance(environ, Mapping):
        raise kering.ConfigurationError("Invalid tock environment mapping")

    # strict - error on unknown tock config props
    unknown = sorted(
        key for key in cfTocks
        if key not in tocks
        and key not in aliases
        and key not in reserved
    )
    if unknown:
        raise kering.ConfigurationError(
            f"Unknown tock configuration key(s): {', '.join(unknown)}"
        )

    # Validate supplied values before applying precedence, skipping reserved keys.
    # Invalid values error even if valid coarse grained overrides are present.
    validTocks = {}
    for tockName, value in cfTocks.items():
        if tockName in tocks:
            validTocks[tockName] = _validateTock(value, f"tocks.{tockName}")
        elif tockName in aliases:
            validTocks[tockName] = _validateTock(value, f"tocks.{tockName}")

    # read any tocks from environment vars, including supported group aliases
    validEnvs = {}
    for tockVals in tocks.values():
        if tockVals.env in environ:
            validEnvs[tockVals.env] = _parseEnvTock(
                environ[tockVals.env], tockVals.env
            )
    for alias in aliases.values():
        if alias.env in environ:
            validEnvs[alias.env] = _parseEnvTock(
                environ[alias.env], alias.env
            )

    # tock resolution precedence is:
    # specific env > coarse env > specific config > coarse config > default
    resolved = {}
    # iterate over flat fine-grained tocks dict
    for tockName, tockVals in tocks.items():
        # specific env
        if tockVals.env in validEnvs:
            value = validEnvs[tockVals.env]
        else:
            value = None
            # coarse env: alias env present means set target vals
            for aliasVals in aliases.values():
                if tockName in aliasVals.targets and aliasVals.env in validEnvs:
                    value = validEnvs[aliasVals.env]
                    break

            # specific config: pull resolved value straight from config
            if value is None and tockName in validTocks:
                value = validTocks[tockName]

            # coarse config: fallback set by coarse alias if specific config hasn't set it
            if value is None:
                for aliasName, aliasVals in aliases.items():
                    if tockName in aliasVals.targets and aliasName in validTocks:
                        value = validTocks[aliasName]
                        break

            # default - from above or caller supplied defaults
            if value is None:
                value = _validateTock(
                    tockVals.default, f"default for tocks.{tockName}"
                )

        resolved[tockName] = value

    return resolved
