# Source provenance

The native implementation and its two Rust tests were extracted from
`rust/src/lib.rs` in [JAMdotTech/PyJAMaz](https://github.com/JAMdotTech/pyjamaz)
at commit `36369976e1b66516c726a2b5e47d6b7a108e2ffe`. Original authorship remains
JAMdot Technologies and the PyJAMaz contributors. The extraction preserves
algorithm, validation, exception, GIL-release, and panic-containment behavior;
only packaging, module naming, and specification comments changed.

The source Cargo manifest declares **GPL-3.0-only**; this package retains that
native component license. The source repository's top-level LICENSE instead
contains Apache-2.0. That original notice is retained verbatim in
`LICENSES/PyJAMaz-Apache-2.0.txt` so the source licensing discrepancy and provenance
are explicit. `LICENSE` contains the GPL version 3 text. No claim is made that
the original source repository's conflicting license metadata was resolved.

The original Cargo.lock supplied every retained dependency version/checksum.
The package root was renamed and dependencies used only by the erasure binding
were pruned; there was no cryptographic dependency upgrade. Direct dependencies
remain PyO3 0.27.2, w3f-bls 0.1.9, and sha2 0.10.9. Their original upstream
licenses continue to apply to those dependencies.

The original Cargo manifest claimed Rust 1.82, but its already locked
`zeroize 1.9.0` and `zeroize_derive 1.5.0` require Rust 1.85. The extracted
manifest records that effective minimum without changing those dependencies.
