from __future__ import annotations

import pytest

from darkhole.crypto import (
    DecryptionError,
    aead_decrypt,
    aead_encrypt,
    blake2b_digest,
    create_session_pair,
    hkdf_blake2b,
    random_bytes,
    serialize_ratchet_state,
    deserialize_ratchet_state,
    x25519_generate_keypair,
    x25519_shared_secret,
)
from darkhole.crypto.kdf_chain import KDFChain
from darkhole.crypto.opaque import OpaqueClient, OpaqueServer


def test_x25519_shared_secret_roundtrip() -> None:
    a = x25519_generate_keypair()
    b = x25519_generate_keypair()
    ab = x25519_shared_secret(a.private, b.public)
    ba = x25519_shared_secret(b.private, a.public)
    assert ab == ba
    assert len(ab) == 32


def test_aead_encrypt_decrypt_and_tamper() -> None:
    key = random_bytes(32)
    pt = b"hello darkhole"

    ct = aead_encrypt(key, pt, aad=b"aad")
    assert aead_decrypt(key, ct, aad=b"aad") == pt

    tampered = bytearray(ct.to_bytes())
    tampered[-1] ^= 0x01
    with pytest.raises(DecryptionError):
        aead_decrypt(key, type(ct).from_bytes(bytes(tampered)), aad=b"aad")


def test_digest_and_hkdf_smoke() -> None:
    d = blake2b_digest(b"abc", digest_size=32)
    assert len(d) == 32

    okm = hkdf_blake2b(b"ikm", salt=b"salt", info=b"info", length=42)
    assert len(okm) == 42


def test_kdf_chain_advances() -> None:
    ck = random_bytes(32)
    chain = KDFChain(ck)
    chain2, mk1 = chain.next()
    chain3, mk2 = chain2.next()
    assert chain2.chain_key != ck
    assert chain3.chain_key != chain2.chain_key
    assert mk1 != mk2


def test_opaque_register_and_login_smoke() -> None:
    password = "correct horse battery staple"

    client = OpaqueClient()
    server = OpaqueServer()

    reg, _static = client.register(password)
    record = server.register_finish(reg)

    client_eph = client.login_start()
    transcript_hash = blake2b_digest(b"opaque/transcript", digest_size=32)

    response, _server_eph, secret = server.login_start(
        record,
        client_ephemeral_public_key=client_eph.public_bytes(),
        transcript_hash=transcript_hash,
    )

    client_session_key, client_mac = client.login_finish(
        password,
        client_ephemeral=client_eph,
        response=response,
        transcript_hash=transcript_hash,
    )
    server_session_key = server.login_finish(secret, client_mac=client_mac, transcript_hash=transcript_hash)

    assert client_session_key == server_session_key

    with pytest.raises(DecryptionError):
        client.login_finish(
            "wrong password",
            client_ephemeral=client_eph,
            response=response,
            transcript_hash=transcript_hash,
        )


def test_ratchet_basic_exchange() -> None:
    alice, bob = create_session_pair(shared_secret=random_bytes(32))

    m1 = alice.encrypt(b"hi bob")
    assert bob.decrypt(m1) == b"hi bob"

    m2 = bob.encrypt(b"hi alice")
    assert alice.decrypt(m2) == b"hi alice"

    m3 = alice.encrypt(b"followup")
    assert bob.decrypt(m3) == b"followup"


def test_ratchet_out_of_order_recovery() -> None:
    alice, bob = create_session_pair(shared_secret=random_bytes(32), max_skip=50)

    msgs = [alice.encrypt(f"msg-{i}".encode()) for i in range(6)]

    # Deliver out-of-order.
    order = [0, 2, 1, 5, 4, 3]
    out = [bob.decrypt(msgs[i]) for i in order]
    assert out == [f"msg-{i}".encode() for i in order]


def test_ratchet_state_serialization_roundtrip() -> None:
    alice, bob = create_session_pair(shared_secret=random_bytes(32))

    m1 = alice.encrypt(b"first")
    assert bob.decrypt(m1) == b"first"

    # Serialize/deserialize bob and ensure it can still decrypt subsequent messages.
    bob_blob = serialize_ratchet_state(bob.state)
    bob2 = type(bob)(deserialize_ratchet_state(bob_blob))

    m2 = alice.encrypt(b"second")
    assert bob2.decrypt(m2) == b"second"


def test_ratchet_post_compromise_self_healing() -> None:
    alice, bob = create_session_pair(shared_secret=random_bytes(32))

    # Initial message.
    m0 = alice.encrypt(b"m0")
    assert bob.decrypt(m0) == b"m0"

    # Attacker obtains a snapshot of Alice's state before she receives Bob's DH ratchet.
    attacker = type(alice)(deserialize_ratchet_state(serialize_ratchet_state(alice.state)))

    # Bob responds, triggering a DH ratchet.
    m1 = bob.encrypt(b"m1")
    assert alice.decrypt(m1) == b"m1"

    # Alice sends a message using her new DH key.
    m2 = alice.encrypt(b"m2")
    assert bob.decrypt(m2) == b"m2"

    # Bob sends again (after ratcheting to Alice's new DH key).
    m3 = bob.encrypt(b"m3")
    assert alice.decrypt(m3) == b"m3"

    # The attacker snapshot should no longer be able to decrypt.
    with pytest.raises(DecryptionError):
        attacker.decrypt(m3)
