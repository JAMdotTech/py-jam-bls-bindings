"""Standalone native contract regressions; no PyJAMaz imports or fixtures."""
import pytest
from jam_bls import (
    bls_public_key, bls_sign, bls_verify, bls_aggregate, bls_verify_aggregate,
)

CONTEXT = b"jam_beefy"
DATA = bytes(range(32))

@pytest.fixture(scope="module")
def signers():
    seeds = [b"first independent JAM BLS signer", b"second independent JAM BLS signer"]
    keys = [bls_public_key(seed) for seed in seeds]
    signatures = [bls_sign(seed, CONTEXT, DATA) for seed in seeds]
    return seeds, keys, signatures


def test_detached_signature_and_key_contract(signers):
    seeds, keys, signatures = signers
    assert len(set(keys)) == 2
    for seed, public, signature in zip(seeds, keys, signatures):
        assert isinstance(public, bytes) and len(public) == 144
        assert isinstance(signature, bytes) and len(signature) == 112
        assert public == bls_public_key(seed)
        assert bls_verify(public, CONTEXT, DATA, signature)
        assert not bls_verify(public, b"other_context", DATA, signature)
        assert not bls_verify(public, CONTEXT, DATA[::-1], signature)
    assert not bls_verify(keys[1], CONTEXT, DATA, signatures[0])


def test_empty_message_and_short_nonempty_seed_are_supported():
    seed = b"x"
    public = bls_public_key(seed)
    signature = bls_sign(seed, CONTEXT, b"")
    assert bls_verify(public, CONTEXT, b"", signature)


@pytest.mark.parametrize("seed", [b"", []])
def test_empty_seed_rejected(seed):
    with pytest.raises(ValueError, match="BLS seed must not be empty"):
        bls_public_key(seed)
    with pytest.raises(ValueError, match="BLS seed must not be empty"):
        bls_sign(seed, CONTEXT, DATA)


@pytest.mark.parametrize("length", [0, 143, 145])
def test_detached_public_key_length_rejected(signers, length):
    with pytest.raises(ValueError, match="public key must be 144 bytes"):
        bls_verify(bytes(length), CONTEXT, DATA, signers[2][0])


@pytest.mark.parametrize("length", [0, 111, 113])
def test_detached_signature_length_rejected(signers, length):
    with pytest.raises(ValueError, match="signature must be 112 bytes"):
        bls_verify(signers[1][0], CONTEXT, DATA, bytes(length))


@pytest.mark.parametrize("field", ["public", "signature"])
def test_malformed_detached_encodings(signers, field):
    public, signature = signers[1][0], signers[2][0]
    if field == "public":
        public = bytes(144)
    else:
        signature = bytes([255]) * 112
    with pytest.raises(ValueError, match="encoding is invalid"):
        bls_verify(public, CONTEXT, DATA, signature)


def test_all_contexts_must_be_nonempty(signers):
    seeds, keys, signatures = signers
    aggregate = bls_aggregate(keys, CONTEXT, DATA, signatures)
    operations = [
        lambda: bls_sign(seeds[0], b"", DATA),
        lambda: bls_verify(keys[0], b"", DATA, signatures[0]),
        lambda: bls_aggregate(keys, b"", DATA, signatures),
        lambda: bls_verify_aggregate(keys, b"", DATA, aggregate),
    ]
    for operation in operations:
        with pytest.raises(ValueError, match="context must not be empty"):
            operation()


def test_aggregate_checks_message_context_and_membership(signers):
    _, keys, signatures = signers
    aggregate = bls_aggregate(keys, CONTEXT, DATA, signatures)
    assert isinstance(aggregate, bytes) and len(aggregate) == 48
    assert bls_verify_aggregate(keys, CONTEXT, DATA, aggregate)
    assert not bls_verify_aggregate(keys, CONTEXT, DATA[::-1], aggregate)
    assert not bls_verify_aggregate(keys, b"other_context", DATA, aggregate)
    assert not bls_verify_aggregate(keys[:1], CONTEXT, DATA, aggregate)
    assert aggregate == bls_aggregate(keys[::-1], CONTEXT, DATA, signatures[::-1])
    assert bls_verify_aggregate(keys[::-1], CONTEXT, DATA, aggregate)


def test_single_signer_aggregate(signers):
    _, keys, signatures = signers
    aggregate = bls_aggregate(keys[:1], CONTEXT, DATA, signatures[:1])
    assert bls_verify_aggregate(keys[:1], CONTEXT, DATA, aggregate)


def test_aggregate_verifies_every_detached_signature(signers):
    _, keys, signatures = signers
    with pytest.raises(ValueError, match="signature 0 is invalid"):
        bls_aggregate(keys, CONTEXT, DATA[::-1], signatures)
    with pytest.raises(ValueError, match="signature 0 is invalid"):
        bls_aggregate(keys, CONTEXT, DATA, signatures[::-1])
    with pytest.raises(ValueError, match="signature 1 encoding is invalid"):
        bls_aggregate(keys, CONTEXT, DATA, [signatures[0], bytes([255]) * 112])


def test_aggregate_rejects_duplicate_keys(signers):
    _, keys, signatures = signers
    with pytest.raises(ValueError, match="duplicate BLS public key at index 1"):
        bls_aggregate([keys[0]] * 2, CONTEXT, DATA, [signatures[0]] * 2)
    aggregate = bls_aggregate(keys, CONTEXT, DATA, signatures)
    with pytest.raises(ValueError, match="duplicate BLS public key at index 1"):
        bls_verify_aggregate([keys[0]] * 2, CONTEXT, DATA, aggregate)


def test_aggregate_rejects_empty_and_mismatched_collections(signers):
    _, keys, signatures = signers
    with pytest.raises(ValueError, match="at least one signer"):
        bls_aggregate([], CONTEXT, DATA, [])
    with pytest.raises(ValueError, match="counts differ"):
        bls_aggregate(keys, CONTEXT, DATA, signatures[:1])
    with pytest.raises(ValueError, match="at least one signer"):
        bls_verify_aggregate([], CONTEXT, DATA, bytes(48))


@pytest.mark.parametrize("length", [0, 47, 49])
def test_aggregate_signature_length_rejected(signers, length):
    with pytest.raises(ValueError, match="aggregate signature must be 48 bytes"):
        bls_verify_aggregate(signers[1], CONTEXT, DATA, bytes(length))


def test_malformed_aggregate_encodings(signers):
    _, keys, signatures = signers
    with pytest.raises(ValueError, match="aggregate signature encoding is invalid"):
        bls_verify_aggregate(keys, CONTEXT, DATA, bytes(48))
    aggregate = bls_aggregate(keys, CONTEXT, DATA, signatures)
    with pytest.raises(ValueError, match="public key 0 encoding is invalid"):
        bls_verify_aggregate([bytes(144)], CONTEXT, DATA, aggregate)
    with pytest.raises(ValueError, match="public key 0 encoding is invalid"):
        bls_aggregate([bytes(144)], CONTEXT, DATA, signatures[:1])


def test_python_argument_conversion():
    with pytest.raises(TypeError):
        bls_public_key(None)
    with pytest.raises(OverflowError):
        bls_public_key([256])
