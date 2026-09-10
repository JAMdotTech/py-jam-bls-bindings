// SPDX-License-Identifier: GPL-3.0-only
// Extracted unchanged in behavior from PyJAMaz; see PROVENANCE.md.
use std::collections::BTreeSet;
use std::panic::{catch_unwind, AssertUnwindSafe};

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use sha2::Sha256;
use w3f_bls::{
    single_pop_aggregator::SignatureAggregatorAssumingPoP, DoublePublicKey, DoublePublicKeyScheme,
    DoubleSignature, Message, PublicKey, PublicKeyInSignatureGroup, SecretKeyVT,
    SerializableToBytes, Signature, Signed, TinyBLS381,
};

type BackendResult<T> = Result<T, String>;

fn guarded<T>(operation: impl FnOnce() -> BackendResult<T>) -> PyResult<T> {
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(message)) => Err(PyValueError::new_err(message)),
        Err(_) => Err(PyValueError::new_err("native backend panicked")),
    }
}

type JamBls = TinyBLS381;

fn bls_secret(seed: &[u8]) -> BackendResult<SecretKeyVT<JamBls>> {
    if seed.is_empty() {
        return Err("BLS seed must not be empty".to_owned());
    }
    Ok(SecretKeyVT::<JamBls>::from_seed(seed))
}

// GP-0.7.2-sec:3.8.2; GP-0.7.2-eq:6.11 (144-byte double public key).
fn bls_public_impl(seed: &[u8]) -> BackendResult<Vec<u8>> {
    let secret = bls_secret(seed)?;
    let public = secret.into_double_public_key().to_bytes();
    if public.len() != 144 {
        return Err(format!(
            "BLS backend returned {} public-key bytes",
            public.len()
        ));
    }
    Ok(public)
}

// GP-0.7.2-eq:18.1; GP-0.7.2-eq:18.2. The caller supplies the context/message.
fn bls_sign_impl(seed: &[u8], context: &[u8], data: &[u8]) -> BackendResult<Vec<u8>> {
    if context.is_empty() {
        return Err("BLS context must not be empty".to_owned());
    }
    let mut secret = bls_secret(seed)?;
    let signature =
        DoublePublicKeyScheme::sign(&mut secret, &Message::new(context, data)).to_bytes();
    if signature.len() != 112 {
        return Err(format!(
            "BLS backend returned {} signature bytes",
            signature.len()
        ));
    }
    Ok(signature)
}

fn bls_verify_impl(
    public_key: &[u8],
    context: &[u8],
    data: &[u8],
    signature: &[u8],
) -> BackendResult<bool> {
    if public_key.len() != 144 {
        return Err("BLS public key must be 144 bytes".to_owned());
    }
    if signature.len() != 112 {
        return Err("BLS signature must be 112 bytes".to_owned());
    }
    if context.is_empty() {
        return Err("BLS context must not be empty".to_owned());
    }
    let public = DoublePublicKey::<JamBls>::from_bytes(public_key)
        .map_err(|_| "BLS public key encoding is invalid".to_owned())?;
    let signature = DoubleSignature::<JamBls>::from_bytes(signature)
        .map_err(|_| "BLS signature encoding is invalid".to_owned())?;
    Ok(public.verify(&Message::new(context, data), &signature))
}

// GP-0.7.2-sec:18. Verify detached Chaum--Pedersen proofs before aggregation.
fn bls_aggregate_impl(
    public_keys: Vec<Vec<u8>>,
    context: &[u8],
    data: &[u8],
    signatures: Vec<Vec<u8>>,
) -> BackendResult<Vec<u8>> {
    if public_keys.is_empty() {
        return Err("BLS aggregate must contain at least one signer".to_owned());
    }
    if public_keys.len() != signatures.len() {
        return Err("BLS public-key and signature counts differ".to_owned());
    }
    if context.is_empty() {
        return Err("BLS context must not be empty".to_owned());
    }
    let message = Message::new(context, data);
    let mut aggregator = SignatureAggregatorAssumingPoP::<JamBls>::new(message.clone());
    let mut seen = BTreeSet::new();
    for (index, (public_bytes, signature_bytes)) in
        public_keys.iter().zip(signatures.iter()).enumerate()
    {
        if !seen.insert(public_bytes.clone()) {
            return Err(format!("duplicate BLS public key at index {index}"));
        }
        let public = DoublePublicKey::<JamBls>::from_bytes(public_bytes)
            .map_err(|_| format!("BLS public key {index} encoding is invalid"))?;
        let signature = DoubleSignature::<JamBls>::from_bytes(signature_bytes)
            .map_err(|_| format!("BLS signature {index} encoding is invalid"))?;
        if !public.verify(&message, &signature) {
            return Err(format!("BLS signature {index} is invalid"));
        }
        aggregator.add_signature(&Signature(signature.0));
        aggregator.add_publickey(&PublicKey(public.1));
        aggregator.add_auxiliary_public_key(&PublicKeyInSignatureGroup(public.0));
    }
    if !aggregator.verify_using_aggregated_auxiliary_public_keys::<Sha256>() {
        return Err("BLS aggregate verification failed".to_owned());
    }
    let aggregate = (&aggregator).signature().to_bytes();
    if aggregate.len() != 48 {
        return Err(format!(
            "BLS backend returned {} aggregate-signature bytes",
            aggregate.len()
        ));
    }
    Ok(aggregate)
}

fn bls_verify_aggregate_impl(
    public_keys: Vec<Vec<u8>>,
    context: &[u8],
    data: &[u8],
    aggregate_signature: &[u8],
) -> BackendResult<bool> {
    if public_keys.is_empty() {
        return Err("BLS aggregate must contain at least one signer".to_owned());
    }
    if context.is_empty() {
        return Err("BLS context must not be empty".to_owned());
    }
    if aggregate_signature.len() != 48 {
        return Err("BLS aggregate signature must be 48 bytes".to_owned());
    }
    let signature = Signature::<JamBls>::from_bytes(aggregate_signature)
        .map_err(|_| "BLS aggregate signature encoding is invalid".to_owned())?;
    let mut aggregator = SignatureAggregatorAssumingPoP::<JamBls>::new(Message::new(context, data));
    aggregator.add_signature(&signature);
    let mut seen = BTreeSet::new();
    for (index, public_bytes) in public_keys.iter().enumerate() {
        if !seen.insert(public_bytes.clone()) {
            return Err(format!("duplicate BLS public key at index {index}"));
        }
        let public = DoublePublicKey::<JamBls>::from_bytes(public_bytes)
            .map_err(|_| format!("BLS public key {index} encoding is invalid"))?;
        aggregator.add_publickey(&PublicKey(public.1));
        aggregator.add_auxiliary_public_key(&PublicKeyInSignatureGroup(public.0));
    }
    Ok(aggregator.verify_using_aggregated_auxiliary_public_keys::<Sha256>())
}

#[pyfunction]
fn bls_public_key(py: Python<'_>, seed: Vec<u8>) -> PyResult<Py<PyBytes>> {
    let public = py.detach(move || guarded(|| bls_public_impl(&seed)))?;
    Ok(PyBytes::new(py, &public).unbind())
}

#[pyfunction]
fn bls_sign(
    py: Python<'_>,
    seed: Vec<u8>,
    context: Vec<u8>,
    data: Vec<u8>,
) -> PyResult<Py<PyBytes>> {
    let signature = py.detach(move || guarded(|| bls_sign_impl(&seed, &context, &data)))?;
    Ok(PyBytes::new(py, &signature).unbind())
}

#[pyfunction]
fn bls_verify(
    py: Python<'_>,
    public_key: Vec<u8>,
    context: Vec<u8>,
    data: Vec<u8>,
    signature: Vec<u8>,
) -> PyResult<bool> {
    py.detach(move || guarded(|| bls_verify_impl(&public_key, &context, &data, &signature)))
}

#[pyfunction]
fn bls_aggregate(
    py: Python<'_>,
    public_keys: Vec<Vec<u8>>,
    context: Vec<u8>,
    data: Vec<u8>,
    signatures: Vec<Vec<u8>>,
) -> PyResult<Py<PyBytes>> {
    let aggregate = py
        .detach(move || guarded(|| bls_aggregate_impl(public_keys, &context, &data, signatures)))?;
    Ok(PyBytes::new(py, &aggregate).unbind())
}

#[pyfunction]
fn bls_verify_aggregate(
    py: Python<'_>,
    public_keys: Vec<Vec<u8>>,
    context: Vec<u8>,
    data: Vec<u8>,
    aggregate_signature: Vec<u8>,
) -> PyResult<bool> {
    py.detach(move || {
        guarded(|| bls_verify_aggregate_impl(public_keys, &context, &data, &aggregate_signature))
    })
}

#[pymodule]
fn _native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(bls_public_key, module)?)?;
    module.add_function(wrap_pyfunction!(bls_sign, module)?)?;
    module.add_function(wrap_pyfunction!(bls_verify, module)?)?;
    module.add_function(wrap_pyfunction!(bls_aggregate, module)?)?;
    module.add_function(wrap_pyfunction!(bls_verify_aggregate, module)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jam_bls_roundtrip_and_context_binding() {
        let seed = b"JAM Beefy test seed";
        let public = bls_public_impl(seed).unwrap();
        let signature = bls_sign_impl(seed, b"jam_beefy", &[7; 32]).unwrap();
        assert_eq!(public.len(), 144);
        assert_eq!(signature.len(), 112);
        assert!(bls_verify_impl(&public, b"jam_beefy", &[7; 32], &signature).unwrap());
        assert!(!bls_verify_impl(&public, b"jam_beefy", &[8; 32], &signature).unwrap());
    }

    #[test]
    fn jam_bls_aggregation_checks_signers_and_context() {
        let seeds = [b"first aggregate seed".as_slice(), b"second aggregate seed"];
        let public_keys: Vec<_> = seeds
            .iter()
            .map(|seed| bls_public_impl(seed).unwrap())
            .collect();
        let signatures: Vec<_> = seeds
            .iter()
            .map(|seed| bls_sign_impl(seed, b"jam_beefy", &[9; 32]).unwrap())
            .collect();
        let aggregate =
            bls_aggregate_impl(public_keys.clone(), b"jam_beefy", &[9; 32], signatures).unwrap();
        assert_eq!(aggregate.len(), 48);
        assert!(
            bls_verify_aggregate_impl(public_keys.clone(), b"jam_beefy", &[9; 32], &aggregate)
                .unwrap()
        );
        assert!(!bls_verify_aggregate_impl(
            public_keys.clone(),
            b"jam_beefy",
            &[8; 32],
            &aggregate
        )
        .unwrap());
        assert!(bls_verify_aggregate_impl(
            vec![public_keys[0].clone(), public_keys[0].clone()],
            b"jam_beefy",
            &[9; 32],
            &aggregate,
        )
        .unwrap_err()
        .contains("duplicate"));
    }
}
