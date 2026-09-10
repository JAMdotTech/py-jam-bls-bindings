"""Native JAM BLS12-381 double-key signatures and verified aggregation."""

from ._native import (
    bls_aggregate,
    bls_public_key,
    bls_sign,
    bls_verify,
    bls_verify_aggregate,
)

__all__ = [
    "bls_public_key", "bls_sign", "bls_verify", "bls_aggregate", "bls_verify_aggregate",
]
