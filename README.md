# py-jam-bls-bindings

Independent Python bindings for JAM BLS12-381 double public keys,
Chaum--Pedersen detached signatures, and verified same-message aggregation.
This package has no PyJAMaz or erasure dependency.

```sh
python -m pip install py-jam-bls-bindings==0.1.0
```

CPython 3.12, 3.13, and 3.14 are supported. Release wheels use `cp312-abi3` for
Linux x86_64/ARM64 (manylinux2014) and macOS x86_64/ARM64 (11.0+). Installing a
wheel needs no Rust compiler. Source builds require Rust 1.85+ and a C linker;
release CI uses Rust 1.85.0 and a portable CPU target.

```python
from jam_bls import bls_public_key, bls_sign, bls_verify

seed = b"example seed: use securely managed key material in applications"
public_key = bls_public_key(seed)
root = bytes(range(32))
signature = bls_sign(seed, b"jam_beefy", root)
assert bls_verify(public_key, b"jam_beefy", root, signature)
```

## Python API

The five functions are exported from `jam_bls`; `jam_bls._native` is private.
Arguments and return values preserve the original PyJAMaz binding contract.
Byte inputs are copied into native storage before the GIL is released.

| Function | Result and contract |
| --- | --- |
| `bls_public_key(seed)` | `bytes`: 144-byte double public key. The seed must be nonempty; derivation is the pinned W3F backend's seed derivation. |
| `bls_sign(seed, context, data)` | `bytes`: 112-byte detached signature, including its Chaum--Pedersen proof. Seed and context must be nonempty; data may be empty. |
| `bls_verify(public_key, context, data, signature)` | `bool`: validates a 144-byte public key and 112-byte signature against the exact nonempty context and data. |
| `bls_aggregate(public_keys, context, data, signatures)` | `bytes`: 48-byte aggregate. Requires matching nonempty lists with unique public keys, and verifies every detached signature before aggregation. |
| `bls_verify_aggregate(public_keys, context, data, aggregate_signature)` | `bool`: checks a 48-byte aggregate using both halves of every unique double public key. The key list and context must be nonempty. |

Native input-validation, decoding, and backend errors raise `ValueError`;
well-formed but non-verifying signatures return `False` from verification.
Python argument conversion retains PyO3's `TypeError`/`OverflowError` behavior.
A backend panic is contained and translated to `ValueError("native backend
panicked")`. Aggregation consumes keys and signatures in corresponding input
order; canonical validator ordering belongs to the caller. These functions do
not choose validators, enforce finality, persist keys, or distribute signatures.

## Specification and evidence

The protocol baseline is Graypaper 0.7.2:

| Rule | Binding responsibility | Evidence |
| --- | --- | --- |
| Section 3.8.2 | W3F BLS12-381 double keys and signatures | Rust/Python roundtrip, malformed encoding, context/message binding tests |
| Equation 6.11 | 144-byte validator BLS key encoding | Length tests and unchanged native key derivation |
| Equations 18.1–18.2 | Signing/verification and aggregation primitives; caller supplies the finalized MMR commitment and `jam_beefy` context | Detached proof validation, aggregate membership/context tests, extraction cross-verification |

The native backend is pinned to `w3f-bls=0.1.9`, `sha2=0.10.9`, and
`pyo3=0.27.2`. Local roundtrips and agreement with the pre-extraction extension
are regression evidence, not independent cryptographic conformance vectors or
a security audit. No public Rust library API or BEEFY distribution protocol is
provided. See [PROVENANCE.md](PROVENANCE.md) for source and license history.

## Development and release

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install build==1.3.0 pytest==8.4.2
cargo test --locked
.venv/bin/python -m build
.venv/bin/python scripts/verify_artifacts.py dist
.venv/bin/python -m pip install --only-binary=:all: --no-deps dist/*.whl
cd /tmp
/path/to/repo/.venv/bin/python -m pytest -q /path/to/repo/tests
```

`python -m build` builds the wheel from its freshly created source distribution.
For a macOS local build with a universal2 Python, explicitly select the native
architecture before building: for ARM64 use `ARCHFLAGS='-arch arm64'`,
`_PYTHON_HOST_PLATFORM=macosx-11.0-arm64`, and `MACOSX_DEPLOYMENT_TARGET=11.0`;
substitute `x86_64` for an Intel host. The artifact checker validates the native
binary's architecture against its wheel tag. Release CI selects each target
through cibuildwheel.
To cross-verify against a retained original extension on a compatible Python:

```sh
python scripts/cross_verify.py /absolute/path/to/_erasure.cpython-313-darwin.so
```

## Publishing

The release workflow builds all four platform wheels from an sdist and tests
installed binaries outside the checkout on CPython 3.12, 3.13, and 3.14.
A matching `vVERSION` or `pypi/vVERSION` tag publishes only after all seventeen
validation jobs pass. The `pypi` GitHub environment uses the organization secret
`PYPI_API_TOKEN`; it must have permission to publish this PyPI project. Token
values are never committed or printed. Package author/contact metadata is
JAMdot Technologies <devops@jamdot.tech>.

The original GitHub-only `v0.1.0` tag is retained as extraction evidence. The
first PyPI release uses `pypi/v0.1.0`, which includes the corrected author
contact and its newly built artifacts. Do not use the earlier GitHub assets as
PyPI release artifacts. The artifact checker enforces the approved author email.

If publishing fails after successful validation, run `release.yml` manually
with the original `release_run_id` and `release_tag`. Recovery verifies the
repository, workflow, tag commit, all required jobs, and immutable artifact IDs
before downloading and checking the exact artifacts. It does not rebuild or
move tags, and does not silently skip previously uploaded files.

Native upgrades require a new package release, lockfile review, regression
evidence, and an explicit consumer dependency change. Builds use `--locked`
and portable CPU targets. See [PROVENANCE.md](PROVENANCE.md) for source history
and licensing.
