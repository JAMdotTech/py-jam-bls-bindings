"""Verify old/extracted native compatibility with a caller-supplied old binary.

This optional migration check is intentionally outside the ordinary test suite:
it must not create a runtime dependency or a fallback to the old extension.
"""
import importlib.util
import sys
from pathlib import Path

import jam_bls


def main():
    old_path = Path(sys.argv[1]).resolve(strict=True)
    spec = importlib.util.spec_from_file_location("_erasure", old_path)
    old = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(old)
    seeds = [b"migration signer zero", b"migration signer one", bytes(range(32))]
    context, message = b"jam_beefy", bytes(range(32))
    keys = [jam_bls.bls_public_key(seed) for seed in seeds]
    assert keys == [old.bls_public_key(seed) for seed in seeds]
    old_sigs = [old.bls_sign(seed, context, message) for seed in seeds]
    new_sigs = [jam_bls.bls_sign(seed, context, message) for seed in seeds]
    for backend, signatures in ((old, new_sigs), (jam_bls, old_sigs)):
        for public, signature in zip(keys, signatures):
            assert backend.bls_verify(public, context, message, signature)
            assert not backend.bls_verify(public, b"other", message, signature)
            assert not backend.bls_verify(public, context, bytes(32), signature)
    old_aggregate = old.bls_aggregate(keys, context, message, old_sigs)
    new_aggregate = jam_bls.bls_aggregate(keys, context, message, new_sigs)
    assert old_aggregate == new_aggregate
    assert old.bls_verify_aggregate(keys, context, message, new_aggregate)
    assert jam_bls.bls_verify_aggregate(keys, context, message, old_aggregate)
    operations = (
        ("bls_public_key", (b"",)),
        ("bls_sign", (seeds[0], b"", message)),
        ("bls_verify", (bytes(143), context, message, old_sigs[0])),
        ("bls_aggregate", ([keys[0]] * 2, context, message, [old_sigs[0]] * 2)),
        ("bls_verify_aggregate", (keys, context, message, bytes(47))),
    )
    for name, args in operations:
        errors = []
        for backend in (old, jam_bls):
            try:
                getattr(backend, name)(*args)
            except Exception as error:
                errors.append((type(error), str(error)))
        assert len(errors) == 2 and errors[0] == errors[1], (name, errors)
    print("Cross-verification passed: 3 keys, bidirectional detached signatures, "
          "identical aggregate bytes, context/message negatives, 5 exception contracts.")


if __name__ == "__main__":
    main()
