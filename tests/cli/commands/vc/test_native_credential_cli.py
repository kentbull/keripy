"""Installed public native credential authoring, separate from registry issuance."""
import hashlib
import json
from uuid import uuid4

import pytest

from keri import Vrsn_1_0, Vrsn_2_0
from keri.acdc import Regery, acdcmap, acdcagg, scheming
from keri.cli.common import setupHby
from keri.app import Organizer
from keri.core import Diger, Schemer, SerderACDC
from keri.vc.proving import credential as legacy_credential
from tests.cli.commands.vc.test_native_registry_cli import kli


pytestmark = pytest.mark.real_store_roots

PASSCODE = '0123456789abcdefghijk'  # Public fixture secret.


@pytest.fixture
def state(tmp_path, request):
    encrypted = getattr(request, 'param', False)
    name, base = 'body-' + uuid4().hex, 'r10body'
    common = ['--name', name, '--base', base]
    auth = ['--passcode', PASSCODE] if encrypted else []
    kli(tmp_path, 'init', *common, '--version', '2.0', *(auth or ['--nopasscode']))
    config = tmp_path / 'identity.json'
    config.write_text(json.dumps(dict(transferable=True, wits=[], toad=0, icount=1, isith='1', ncount=1, nsith='1')))
    for alias in ('issuer', 'recipient'):
        kli(tmp_path, 'incept', *common, *auth, '--version', '2.0', '--alias', alias, '--file', str(config))
    for alias, registry in (('issuer', 'native'), ('recipient', 'foreign')):
        kli(tmp_path, 'vc', 'registry', 'incept', *common, *auth, '--version', '2.0',
            '--alias', alias, '--registry-name', registry)
    hby = setupHby(name=name, base=base, bran=PASSCODE if encrypted else None, noPrompt=True, version=Vrsn_2_0)
    try:
        parties = {alias: hby.habByName(alias).pre for alias in ('issuer', 'recipient')}
    finally:
        hby.close()
    return dict(name=name, base=base, common=common, auth=auth, encrypted=encrypted, **parties)


def opened(state):
    return setupHby(name=state['name'], base=state['base'], bran=PASSCODE if state['encrypted'] else None,
                    noPrompt=True, version=Vrsn_2_0)


def snapshot(state):
    hby = opened(state)
    rgy = Regery(hby=hby, name=state['name'], base=state['base'])
    try:
        return dict(kel={pre: hab.kever.serder.said for pre, hab in hby.habs.items()},
                    registries={name: (reg.regk, reg.head.qb64 if reg.head else None, reg.sn) for name, reg in rgy.names.items()},
                    events=[(key, value.raw) for key, value in rgy.baser.evts.getTopItemIter()],
                    roots=list(hby.ks.rroots.getTopItemIter()), aeid=hby.mgr.aeid,
                    keeper=[(bytes(key), hashlib.sha256(bytes(value)).hexdigest())
                            for key, value in hby.ks.getTopItemIter(db=hby.ks.pris.sdb)])
    finally:
        rgy.close()
        hby.close()


def create(tmp_path, state, filename, *args, succeeds=True, alias='issuer', registry='native', auth=None):
    return kli(tmp_path, 'vc', 'create', *state['common'], *(state['auth'] if auth is None else auth),
               '--alias', alias, '--registry-name', registry, '--recipient', 'recipient',
               '--version', '2.0', '--output', str(tmp_path / filename), *args, succeeds=succeeds)


@pytest.mark.parametrize('state', [False, True], indirect=True, ids=['unencrypted', 'encrypted'])
def test_native_acm_body_uses_imported_schema_and_is_deterministic_without_issuing(tmp_path, state):
    schema = Schemer(sed={'$id': '', '$schema': scheming.SchemaDialect, 'type': 'object', 'version': '1.0.0',
        'required': ['a'], 'properties': {'a': {'type': 'object', 'required': ['role'],
        'properties': {'role': {'const': 'member'}}}}})
    (tmp_path / 'schema.json').write_bytes(schema.raw)
    kli(tmp_path, 'vc', 'schema', 'import_', *state['common'], *state['auth'], '--schema', str(tmp_path / 'schema.json'))
    before = snapshot(state)
    data = json.dumps(dict(d='', role='member'))
    edges = json.dumps(dict(d='', ref=dict(d='', n=Diger(ser=b'public predecessor').qb64)))
    rules = json.dumps(dict(d='', usage='test'))
    for filename in ('one.cesr', 'two.cesr'):
        result = create(tmp_path, state, filename, '--schema', schema.said, '--data', data,
                        '--edges', edges, '--rules', rules)
        assert json.loads(result)['body_created'] and json.loads(result)['registry_issued'] is False
        assert json.loads(result)['admitted'] is False
    assert (tmp_path / 'one.cesr').read_bytes() == (tmp_path / 'two.cesr').read_bytes()
    body = SerderACDC(raw=(tmp_path / 'one.cesr').read_bytes())
    assert body.verify() and body.pvrsn == Vrsn_2_0 and body.ilk == 'acm'
    hby = opened(state)
    try:
        assert body.israid == hby.habByName('issuer').pre and body.iseaid == hby.habByName('recipient').pre
        assert body.regid == before['registries']['native'][0] and body.schema == schema.said
        assert body.edge['ref']['n'] == Diger(ser=b'public predecessor').qb64 and body.rule['usage'] == 'test'
        assert scheming.validateSchema(body, hby.db)
    finally:
        hby.close()
    create(tmp_path, state, 'bad-schema-data', '--schema', schema.said,
           '--data', '{"d":"","role":"not-member"}', succeeds=False)
    assert not (tmp_path / 'bad-schema-data').exists()
    if not state['encrypted']:
        create(tmp_path, state, 'global-passcode.cesr', '--schema', schema.said, '--data', data,
               '--edges', edges, '--rules', rules, auth=['--passcode', PASSCODE])
        assert (tmp_path / 'global-passcode.cesr').read_bytes() == body.raw
    assert snapshot(state) == before


@pytest.mark.parametrize('ilk', ['act', 'acg'])
def test_native_fixed_body_and_verified_full_body_roundtrip(tmp_path, state, ilk):
    hby = opened(state)
    try:
        recipient = hby.habByName('recipient').pre
    finally:
        hby.close()
    payload = dict(d='', role='member') if ilk == 'act' else ['', dict(d='', i=recipient, role='member'), dict(d='', claim='public')]
    before = snapshot(state)
    create(tmp_path, state, 'body.cesr', '--ilk', ilk, '--data', json.dumps(payload))
    body = SerderACDC(raw=(tmp_path / 'body.cesr').read_bytes())
    assert body.verify() and body.ilk == ilk and body.iseaid == recipient
    (tmp_path / 'full.json').write_text(json.dumps(body.sad))
    create(tmp_path, state, 'full.cesr', '--credential', '@' + str(tmp_path / 'full.json'))
    assert (tmp_path / 'full.cesr').read_bytes() == body.raw
    assert snapshot(state) == before


def test_native_body_refuses_invalid_scope_schema_and_options_before_mutation(tmp_path, state):
    hby = opened(state)
    rgy = Regery(hby=hby, name=state['name'], base=state['base'])
    try:
        pending = rgy.makeRegistry('pending', state['issuer'])
        assert pending.head is None
    finally:
        rgy.close()
        hby.close()
    before = snapshot(state)
    data = json.dumps(dict(d='', role='member'))
    for name, options in (
        ('foreign-registry', ['--registry-name', 'foreign', '--data', data]),
        ('unknown-registry', ['--registry-name', 'absent', '--data', data]),
        ('unaccepted-registry', ['--registry-name', 'pending', '--data', data]),
        ('unknown-issuer', ['--alias', 'absent', '--data', data]),
        ('bad-recipient', ['--recipient', 'not-an-aid', '--data', data]),
        ('conflicting-recipient', ['--data', json.dumps(dict(d='', i=state['issuer'], role='member'))]),
        ('missing-schema', ['--schema', Diger(ser=b'unknown schema').qb64, '--data', data]),
        ('trailing-schema', ['--schema', Diger(ser=b'schema').qb64 + 'AAAA', '--data', data]),
        ('bad-data', ['--data', '[]']),
        ('private', ['--private', '--data', data]),
        ('time', ['--time', '2026-11-03T00:00:00.000000+00:00', '--data', data]),
    ):
        create(tmp_path, state, name, *options, succeeds=False)
        assert not (tmp_path / name).exists()
        assert snapshot(state) == before
    create(tmp_path, state, 'good', '--data', data)
    body = SerderACDC(raw=(tmp_path / 'good').read_bytes())
    for field, value in (('i', body.iseaid), ('rd', before['registries']['foreign'][0]), ('a', dict(d='', i=body.israid))):
        changed = dict(body.sad, **{field: value})
        (tmp_path / 'changed.json').write_text(json.dumps(changed))
        create(tmp_path, state, 'refused', '--credential', '@' + str(tmp_path / 'changed.json'), succeeds=False)
        assert not (tmp_path / 'refused').exists() and snapshot(state) == before


@pytest.mark.parametrize('state', [True], indirect=True)
def test_native_body_wrong_unlock_preserves_encrypted_keeper_and_existing_output(tmp_path, state):
    before = snapshot(state)
    create(tmp_path, state, 'wrong', '--data', '{"d":""}', auth=['--passcode', 'abcdefghijklmnopqrstu'], succeeds=False)
    assert not (tmp_path / 'wrong').exists() and snapshot(state) == before
    (tmp_path / 'existing').write_bytes(b'keep public artifact')
    create(tmp_path, state, 'existing', '--data', '{"d":""}', succeeds=False)
    assert (tmp_path / 'existing').read_bytes() == b'keep public artifact' and snapshot(state) == before


def test_verified_full_body_refuses_other_issuer_registry_aggregate_issuee_and_legacy_version(tmp_path, state):
    before = snapshot(state)
    regid = before['registries']['native'][0]
    common = dict(israid=state['issuer'], regid=regid, iseaid=state['recipient'], attribute=dict(d='', role='member'))
    wrong_issuer = acdcmap(**dict(common, israid=state['recipient']))
    wrong_registry = acdcmap(**dict(common, regid=before['registries']['foreign'][0]))
    wrong_issuee = acdcagg(israid=state['issuer'], regid=regid, aggregate=['', dict(d='', i=state['issuer'])])
    legacy = legacy_credential(schema=Diger(ser=b'legacy schema').qb64, issuer=state['issuer'],
                               recipient=state['recipient'], data=dict(role='member'), status=regid, version=Vrsn_1_0)
    for body in (wrong_issuer, wrong_registry, wrong_issuee, legacy):
        assert body.verify()
        (tmp_path / 'full.json').write_text(json.dumps(body.sad))
        create(tmp_path, state, 'refused', '--credential', '@' + str(tmp_path / 'full.json'), succeeds=False)
        assert not (tmp_path / 'refused').exists() and snapshot(state) == before


def test_accepted_group_can_create_body_without_signing_or_registry_progress(tmp_path, state):
    hby = opened(state)
    try:
        member = hby.habByName('issuer')
        group = hby.makeGroupHab(group='group', mhab=member, smids=[member.pre], isith='1', nsith='1',
                                 data=[dict(d=member.kever.serder.said)], version=Vrsn_2_0)
        gid = group.pre
        assert group.accepted and gid != member.pre
    finally:
        hby.close()
    kli(tmp_path, 'vc', 'registry', 'incept', *state['common'], '--alias', 'group', '--registry-name', 'group',
        '--version', '2.0', '--usage', 'public group credential')
    before = snapshot(state)
    create(tmp_path, state, 'group.cesr', '--data', '{"d":"","role":"member"}', alias='group', registry='group')
    body = SerderACDC(raw=(tmp_path / 'group.cesr').read_bytes())
    assert body.verify() and body.israid == gid and body.regid == before['registries']['group'][0]
    assert snapshot(state) == before


def test_existing_v1_create_still_issues_using_legacy_registry(tmp_path):
    name, base = 'legacy-body-' + uuid4().hex, 'r10body'
    common = ['--name', name, '--base', base]
    kli(tmp_path, 'init', *common, '--nopasscode', '--version', '1.0')
    config = tmp_path / 'issuer.json'
    config.write_text(json.dumps(dict(transferable=True, wits=[], toad=0, icount=1, isith='1', ncount=1, nsith='1')))
    kli(tmp_path, 'incept', *common, '--alias', 'issuer', '--file', str(config), '--version', '1.0')
    kli(tmp_path, 'vc', 'registry', 'incept', *common, '--alias', 'issuer', '--registry-name', 'legacy')
    schema = Schemer(sed={'$id': '', '$schema': scheming.SchemaDialect, 'type': 'object'})
    (tmp_path / 'schema.json').write_bytes(schema.raw)
    kli(tmp_path, 'vc', 'schema', 'import_', *common, '--schema', str(tmp_path / 'schema.json'))
    output = kli(tmp_path, 'vc', 'create', *common, '--alias', 'issuer', '--registry-name', 'legacy',
                 '--schema', schema.said, '--data', '{"role":"member"}')
    assert 'has been created' in output and 'body_created' not in output


def test_explicit_recipient_aid_cannot_be_redirected_by_a_contact_alias(tmp_path, state):
    hby = opened(state)
    try:
        Organizer(hby).update(state['issuer'], dict(alias=state['recipient']))
    finally:
        hby.close()
    before = snapshot(state)
    create(tmp_path, state, 'literal.cesr', '--data', '{"d":"","role":"member"}', '--recipient', state['recipient'])
    body = SerderACDC(raw=(tmp_path / 'literal.cesr').read_bytes())
    assert body.iseaid == state['recipient']
    assert snapshot(state) == before
