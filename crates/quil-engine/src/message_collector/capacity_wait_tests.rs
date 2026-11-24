//! Capacity certificates beside storage epoch proofs that fill every GLOBAL
//! proposal's seal share. Taken only after the proofs, no certificate rode
//! GLOBAL frames 1123400-1123919 (2026-11-24): in 970 of 980 proposals the
//! proofs left no room for one. Taken ahead of the proofs without a share,
//! five certificates crowded the proofs out (2026-11-08). The sizes are
//! written out, not read from the constants, so the tests also run on a
//! build without them.

use super::*;
use quil_execution::global_intrinsic::storage_epoch_proof::{
    SeatProof, StorageEpochProof, TYPE_STORAGE_EPOCH_PROOF,
};
use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};

/// About the size of a settlement proof on mainnet: thirteen fill the 8 MiB
/// seal share to within 0.4 MB, less than a certificate.
const LEN: usize = 620_000;
/// Proofs arriving for each proposal: more than the seal share holds.
const PROOFS_PER_FRAME: u32 = 15;
/// A mainnet certificate's proof bytes (797-815 KB a message).
const CERTIFICATE: usize = 800_000;
/// The epoch whose seats the proofs seal.
const EPOCH: u64 = 1478;
/// A GLOBAL proposal's message bytes, its seal share and capacity share.
const PROPOSAL: usize = 12 << 20;
const SHARE: usize = 8 << 20;
const CAPACITY_SHARE: usize = 2 << 20;
/// The first GLOBAL frame proposed.
const FIRST: u64 = 100;

fn bundle(inner_type_prefix: u32, inner_bytes: Vec<u8>) -> Vec<u8> {
    CanonicalMessageBundle {
        requests: vec![Some(CanonicalMessageRequest {
            inner_type_prefix,
            inner_bytes,
        })],
        timestamp: 0,
    }
    .to_canonical_bytes()
    .unwrap()
}

/// Member `id`'s seal proof for one seat, of `LEN` proof bytes.
fn seal(id: u32) -> Vec<u8> {
    let mut member = [0u8; 32];
    member[..4].copy_from_slice(&id.to_be_bytes());
    let mut proof = vec![0u8; LEN];
    proof[..4].copy_from_slice(&id.to_be_bytes());
    let proof = StorageEpochProof {
        member,
        seats: vec![SeatProof {
            shard_filter: member.to_vec(),
            epoch: EPOCH,
            seals: true,
            ..Default::default()
        }],
        proof,
    };
    bundle(TYPE_STORAGE_EPOCH_PROOF, proof.to_canonical_bytes())
}

/// Member `member`'s capacity certificate for one sector.
fn certificate(member: u8) -> Vec<u8> {
    use quil_crypto::persistent_storage::{Certificate, Profile};
    use quil_execution::global_intrinsic::persistent_storage::CapacityMessage;
    let message = CapacityMessage {
        member: [member; 32],
        epoch: 1500,
        certificate: Certificate {
            profile: Profile::Eleven,
            sector: [member; 32],
            n: 32,
            columns: [0; 32],
            labels: [0; 32],
        },
        signed_at: 0,
        signature: Vec::new(),
        proof: vec![member; CERTIFICATE],
    };
    bundle(
        TYPE_STORAGE_EPOCH_PROOF,
        message.envelope().to_canonical_bytes(),
    )
}

/// A GLOBAL archive's collector, keeping class shares.
fn archive() -> MessageCollector {
    let mc = MessageCollector::new();
    mc.set_class_shares();
    mc
}

fn add(mc: &MessageCollector, rank: u64, message: &[u8]) {
    assert_eq!(
        mc.add_message_outcome(rank, message.to_vec()),
        SubmitOutcome::Accepted,
        "capacity-wait premise: the archive holds every message sent"
    );
}

/// The proposal of `frame` of `max_bytes`, after `PROOFS_PER_FRAME` more
/// proofs arrive (numbered from `*next`); its frame finalizes what it took.
/// Returns what it took and how many proofs, those held over from an
/// earlier frame too.
fn propose(
    mc: &MessageCollector,
    frame: u64,
    max_bytes: usize,
    next: &mut u32,
) -> (Vec<Vec<u8>>, usize) {
    let proofs: Vec<Vec<u8>> = (0..PROOFS_PER_FRAME).map(|i| seal(*next + i)).collect();
    *next += PROOFS_PER_FRAME;
    assert!(
        proofs.iter().map(Vec::len).sum::<usize>() > SHARE,
        "capacity-wait premise: the proofs offered fill the seal share"
    );
    for proof in &proofs {
        add(mc, frame, proof);
    }
    let taken: Vec<Vec<u8>> = mc
        .snapshot_for_proposal(frame, max_bytes, 100_000, Some(frame), &[])
        .unwrap()
        .into_iter()
        .map(|(data, _)| data)
        .collect();
    let proof_len = seal(0).len();
    let proofs_taken = taken.iter().filter(|data| data.len() == proof_len).count();
    mc.mark_finalized(&taken);
    mc.prune_after_finalization(frame);
    (taken, proofs_taken)
}

/// A certificate rides the second proposal after it arrives while storage
/// epoch proofs fill every proposal's seal share: the first leaves it out,
/// the next takes it ahead of the proofs. Its sender resends it each frame,
/// as a member's node does until a frame carries it.
#[test]
fn a_certificate_rides_while_storage_epoch_proofs_fill_every_seal_share() {
    let mc = archive();
    let certificate = certificate(7);
    let mut next = 1;
    let mut rode = None;
    for frame in FIRST..FIRST + 10 {
        // Held already, a copy sent again is a duplicate.
        let outcome = mc.add_message_outcome(frame, certificate.clone());
        assert!(
            outcome == SubmitOutcome::Accepted
                || (frame > FIRST && outcome == SubmitOutcome::Duplicate),
            "capacity-wait premise: the archive holds the certificate at frame {frame}: {outcome:?}"
        );
        let (taken, proofs) = propose(&mc, frame, PROPOSAL, &mut next);
        assert!(
            proofs >= 12,
            "capacity-wait premise: frame {frame} carried {proofs} proofs, short of the seal share"
        );
        if taken.contains(&certificate) {
            rode = Some(frame);
            break;
        }
    }
    eprintln!("REACH capacity-wait rode={rode:?}");
    let rode = rode.unwrap_or_else(|| {
        panic!("capacity-wait starved: storage epoch proofs filled the seal share of 10 proposals and none took the certificate")
    });
    assert!(
        rode <= FIRST + 1,
        "capacity-wait bound: the certificate rode frame {rode}, over a proposal after the first left it out"
    );
}

/// Certificates a proposal left out take at most their share of the next
/// (2 MiB, two of them) ahead of the storage epoch proofs, and the proofs
/// keep the rest of the seal share: six certificates ahead of every proof
/// left room for five (2026-11-08). The proposal of 8 MiB is what a GLOBAL
/// proposal of 12 MiB leaves once shard proofs take their floor (4 MiB).
#[test]
fn certificates_left_out_take_at_most_their_share_ahead_of_storage_epoch_proofs() {
    let mc = archive();
    let certificates: Vec<Vec<u8>> = (1..=6).map(certificate).collect();
    for certificate in &certificates {
        add(&mc, FIRST, certificate);
    }
    let mut next = 1;
    let count = |taken: &[Vec<u8>]| {
        taken
            .iter()
            .filter(|data| certificates.contains(data))
            .map(Vec::len)
            .sum::<usize>()
    };
    let (taken, _) = propose(&mc, FIRST, SHARE, &mut next);
    assert_eq!(
        count(&taken),
        0,
        "capacity-wait premise: the first proposal leaves the certificates out"
    );
    let (taken, proofs) = propose(&mc, FIRST + 1, SHARE, &mut next);
    let bytes = count(&taken);
    eprintln!("REACH capacity-wait share certificate_bytes={bytes} proofs={proofs}");
    assert!(
        bytes <= CAPACITY_SHARE,
        "capacity-wait share: certificates took {bytes} bytes of the proposal ahead of the proofs"
    );
    let floor = (SHARE - CAPACITY_SHARE) / (LEN + 1024);
    assert!(
        proofs >= floor,
        "capacity-wait proofs-keep: {proofs} storage epoch proofs rode beside the certificates, under {floor}"
    );
}

/// Of the certificates proposals left out, those left first go first: one
/// left out by the first proposal rides before others the second left out,
/// although these keep arriving.
#[test]
fn certificates_left_out_longest_go_first() {
    let mc = archive();
    let first: Vec<Vec<u8>> = (1..=3).map(certificate).collect();
    let later: Vec<Vec<u8>> = (4..=6).map(certificate).collect();
    for certificate in &first {
        add(&mc, FIRST, certificate);
    }
    let mut next = 1;
    let mut rode: HashMap<Vec<u8>, u64> = HashMap::new();
    for frame in FIRST..FIRST + 3 {
        if frame == FIRST + 1 {
            for certificate in &later {
                add(&mc, frame, certificate);
            }
        }
        let (taken, _) = propose(&mc, frame, PROPOSAL, &mut next);
        for data in taken {
            if first.contains(&data) || later.contains(&data) {
                rode.insert(data, frame);
            }
        }
    }
    let frames: Vec<Option<u64>> = first.iter().map(|c| rode.get(c).copied()).collect();
    eprintln!("REACH capacity-wait order first={frames:?}");
    for (i, frame) in frames.iter().enumerate() {
        assert!(
            frame.is_some_and(|frame| frame <= FIRST + 2),
            "capacity-wait order: certificate {} left out at frame {FIRST} rode {frame:?}, after those left out later",
            i + 1
        );
    }
}
