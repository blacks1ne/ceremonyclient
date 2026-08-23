//! Serialize + verify simplex FINALIZATION certificates for reward attribution
//! (task #61). A commonware‑simplex‑finalized app‑shard frame carries no BLS
//! aggregate signature in its header — its authenticity is the simplex quorum
//! certificate (`Finalization` = the finalized proposal + a Falcon
//! [`Certificate`](crate::falcon_scheme::Certificate) over it). To credit the
//! shard's work at the GLOBAL level, the archive re‑verifies that certificate
//! against the shard committee (the active provers' Falcon keys) and reads the
//! signer set from the cert's `Signers` bitmap.
//!
//! - [`encode_finalization`] serializes the `Finalization` for the coverage
//!   bundle (called on the finalize path, via the seam finalizer).
//! - [`verify_finalization`] rebuilds the committee verifier, decodes + verifies
//!   the cert, binds it to the frame identity digest, and returns the signing
//!   members' public keys (for reward distribution).

use commonware_codec::{Encode, Read};
use commonware_consensus::simplex::types::Finalization;
use commonware_cryptography::{certificate::Scheme as _, sha256::Digest as Sha256Digest};
use commonware_utils::ordered::{Quorum as _, Set};
use std::fmt;

use crate::falcon_base::FalconPublicKey;
use crate::falcon_simplex::SimplexFalconScheme;

/// The concrete finalization certificate type for Quilibrium consensus.
pub type AppFinalization = Finalization<SimplexFalconScheme, Sha256Digest>;

/// Metadata obtainable by decoding a serialized finalization under a candidate
/// committee cardinality.  Signer entries are positions in Commonware's
/// canonical (sorted) committee, not public keys.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedFinalizationEvidence {
    pub committee_size: usize,
    pub signer_indices: Vec<usize>,
    pub payload_matches_expected_digest: bool,
}

/// Discriminator prefixing a CW finalization cert when it rides in a frame
/// header's `public_key_signature_bls48581` field (which legacy frames used for
/// a BLS aggregate). Lets the global reward path tell a CW cert from a BLS agg.
pub const CW_CERT_MAGIC: &[u8] = b"CWCT";

/// Why a serialized app-shard CW finalization did not verify.  This is kept
/// deliberately metadata-only: callers can log it without exposing a full
/// certificate or committee member list.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FinalizationVerificationError {
    EmptyCommittee,
    InvalidCommitteeKey {
        members: usize,
        parsed: usize,
    },
    DuplicateCommitteeKeys {
        members: usize,
    },
    DecodeFailed {
        committee_size: usize,
    },
    PayloadMismatch,
    InsufficientSigners {
        signers: usize,
        quorum: usize,
    },
    SignatureVerificationFailed {
        signers: usize,
        committee_size: usize,
    },
}

impl fmt::Display for FinalizationVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyCommittee => write!(f, "empty reconstructed committee"),
            Self::InvalidCommitteeKey { members, parsed } => write!(
                f,
                "reconstructed committee contains invalid Falcon keys (parsed {parsed}/{members})"
            ),
            Self::DuplicateCommitteeKeys { members } => write!(
                f,
                "reconstructed committee contains duplicate Falcon keys ({members} entries)"
            ),
            Self::DecodeFailed { committee_size } => write!(
                f,
                "certificate decode failed under reconstructed committee size {committee_size}"
            ),
            Self::PayloadMismatch => write!(f, "certificate proposal digest does not bind to frame output"),
            Self::InsufficientSigners { signers, quorum } => write!(
                f,
                "certificate has {signers} signers, below quorum {quorum}"
            ),
            Self::SignatureVerificationFailed { signers, committee_size } => write!(
                f,
                "Falcon certificate verification failed ({signers} signers, reconstructed committee size {committee_size})"
            ),
        }
    }
}

/// Wrap a serialized finalization cert with [`CW_CERT_MAGIC`] for the header sig field.
pub fn wrap_cert_for_header(cert: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(CW_CERT_MAGIC.len() + cert.len());
    v.extend_from_slice(CW_CERT_MAGIC);
    v.extend_from_slice(cert);
    v
}

/// If `sig_field` carries a CW cert (magic prefix), return the raw cert bytes.
pub fn unwrap_cert_from_header(sig_field: &[u8]) -> Option<&[u8]> {
    sig_field.strip_prefix(CW_CERT_MAGIC)
}

/// Serialize a finalization certificate (proposal + Falcon cert) to bytes for
/// carrying in the coverage bundle.
pub fn encode_finalization(f: &AppFinalization) -> Vec<u8> {
    f.encode().to_vec()
}

/// Decode a certificate under bounded candidate committee sizes for incident
/// diagnostics.  This performs no signature verification: it only establishes
/// which bitmap cardinalities can parse the complete encoded certificate and
/// exposes their signer positions.  Call this only on a verification failure.
///
/// Requiring the decoder to consume every byte prevents a candidate size from
/// being reported merely because it parsed a valid prefix.
pub fn inspect_finalization_decodes(
    bytes: &[u8],
    expected_digest: [u8; 32],
    candidate_committee_sizes: impl IntoIterator<Item = usize>,
) -> Vec<DecodedFinalizationEvidence> {
    candidate_committee_sizes
        .into_iter()
        .filter(|size| *size > 0)
        .filter_map(|committee_size| {
            let mut cursor: &[u8] = bytes;
            let finalization =
                <AppFinalization as Read>::read_cfg(&mut cursor, &committee_size).ok()?;
            if !cursor.is_empty() {
                return None;
            }
            Some(DecodedFinalizationEvidence {
                committee_size,
                signer_indices: finalization
                    .certificate
                    .signers
                    .iter()
                    .map(usize::from)
                    .collect(),
                payload_matches_expected_digest: finalization.proposal.payload
                    == Sha256Digest(expected_digest),
            })
        })
        .collect()
}

/// Verify a serialized [`AppFinalization`] against a shard committee.
///
/// - `bytes`: the serialized finalization certificate.
/// - `committee_pubkeys`: the shard's committee members' Falcon public keys
///   (the active provers under the filter; any order — the `Set` sorts).
/// - `namespace`: the consensus domain, `b"appshard" ++ app_address`.
/// - `expected_digest`: `Poseidon(header.output)` — the frame identity the cert
///   must bind to.
///
/// Returns the public keys of the committee members that signed (a quorum, for
/// reward attribution), or `None` if the cert is malformed, below quorum, has a
/// bad signature, or does not bind to `expected_digest`.
pub fn verify_finalization(
    bytes: &[u8],
    committee_pubkeys: &[Vec<u8>],
    namespace: &[u8],
    expected_digest: [u8; 32],
) -> Option<Vec<Vec<u8>>> {
    verify_finalization_detailed(bytes, committee_pubkeys, namespace, expected_digest).ok()
}

/// As [`verify_finalization`], but preserves the failure category for
/// diagnostics. This lets an archive-bootstrap client distinguish a malformed
/// stored certificate from a historical-committee reconstruction mismatch.
pub fn verify_finalization_detailed(
    bytes: &[u8],
    committee_pubkeys: &[Vec<u8>],
    namespace: &[u8],
    expected_digest: [u8; 32],
) -> Result<Vec<Vec<u8>>, FinalizationVerificationError> {
    // Rebuild the committee verifier (same Set every node builds — it sorts).
    let pks: Vec<FalconPublicKey> = committee_pubkeys
        .iter()
        .filter_map(|b| FalconPublicKey::from_bytes(b))
        .collect();
    if pks.is_empty() {
        return Err(FinalizationVerificationError::EmptyCommittee);
    }
    if pks.len() != committee_pubkeys.len() {
        return Err(FinalizationVerificationError::InvalidCommitteeKey {
            members: committee_pubkeys.len(),
            parsed: pks.len(),
        });
    }
    let set: Set<FalconPublicKey> =
        pks.try_into()
            .map_err(|_| FinalizationVerificationError::DuplicateCommitteeKeys {
                members: committee_pubkeys.len(),
            })?;
    let n = set.len();
    let scheme = SimplexFalconScheme::verifier(namespace, set);

    // Decode the finalization (cfg = committee size, bounds the Signers bitmap).
    let mut cursor: &[u8] = bytes;
    let f = <AppFinalization as Read>::read_cfg(&mut cursor, &n)
        .map_err(|_| FinalizationVerificationError::DecodeFailed { committee_size: n })?;

    // Bind the certificate to the frame identity we are crediting.
    if f.proposal.payload != Sha256Digest(expected_digest) {
        return Err(FinalizationVerificationError::PayloadMismatch);
    }

    // Verify quorum + every Falcon signature over the finalize subject.
    let signer_count = f.certificate.signers.count();
    let quorum = scheme.participants().quorum::<commonware_utils::N3f1>() as usize;
    if signer_count < quorum {
        return Err(FinalizationVerificationError::InsufficientSigners {
            signers: signer_count,
            quorum,
        });
    }
    if !scheme.verify_finalization_cert(&f.proposal, &f.certificate) {
        return Err(FinalizationVerificationError::SignatureVerificationFailed {
            signers: signer_count,
            committee_size: n,
        });
    }

    // Read the signing members off the cert's `Signers` bitmap.
    let mut signers = Vec::with_capacity(f.certificate.signers.count());
    for idx in f.certificate.signers.iter() {
        if let Some(pk) = scheme.participants().key(idx) {
            signers.push(pk.as_ref().to_vec());
        }
    }
    Ok(signers)
}

#[cfg(test)]
mod tests {
    use super::inspect_finalization_decodes;

    #[test]
    fn inspection_rejects_malformed_and_trailing_certificate_bytes() {
        assert!(inspect_finalization_decodes(&[0xff, 0x00], [0; 32], 1..=8).is_empty());
    }
}
