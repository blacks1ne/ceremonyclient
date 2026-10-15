//! Bounded synthetic A/B: rebuild the full commitment versus persistent,
//! selected-block reads. Uses a temporary database, never a node store.
use std::{sync::Arc, time::Instant};
use quil_crypto::{porep, sdr};
use quil_store::{replica_store::ReplicaStore, RocksDb};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = std::env::args().nth(1).map(|v| v.parse()).transpose()?.unwrap_or(1024 * 1024usize);
    if bytes == 0 || bytes > 8 * 1024 * 1024 { return Err("benchmark size must be 1..8MiB".into()); }
    quil_crypto::init();
    let dir = tempfile::tempdir()?;
    let db = Arc::new(RocksDb::open(dir.path())?);
    let store = ReplicaStore::new(db.clone());
    let poly = quil_types::consensus::STORAGE_BLOCK_POLY_SIZE;
    let data = vec![0x51; bytes];
    let start = Instant::now();
    let (replica, leaf) = sdr::build_leaf_replica(&data, b"member", b"leaf", 7, poly, &sdr::SdrParams::default());
    let seal_ms = start.elapsed().as_millis();
    let start = Instant::now();
    store.put_prepared(7, b"leaf", &replica, &leaf)?;
    let persist_ms = start.elapsed().as_millis();
    // Old representation and algorithm, through the real persistent store API.
    store.put(7, b"baseline", &replica)?;
    let mut timings = Vec::new();
    for beacon in 0..3 {
        let rho = [beacon; 32];
        let start = Instant::now();
        let bytes = store.get(7, b"baseline")?.ok_or("missing baseline")?;
        let rebuilt = sdr::commit_leaf(&bytes, poly);
        let expected = porep::build_storage_opening(&bytes, &rebuilt, b"leaf", 7, b"member", 0, &rho, poly);
        let baseline_us = start.elapsed().as_micros();
        let start = Instant::now();
        let prepared = store.prepared(7, b"leaf")?.ok_or("missing prepared replica")?;
        let actual = porep::build_storage_opening_from_reader(&prepared, b"leaf", 7, b"member", 0, &rho, poly)?;
        let prepared_us = start.elapsed().as_micros();
        if expected.to_proto() != actual.to_proto() { return Err("proofs differ".into()); }
        let (att, root) = porep::build_frame_storage_attestation(&[actual], 100, &rho, &[], poly);
        if !porep::verify_frame_storage_attestation_registered(&root, &att, 100, &rho, &[], poly, 7,
            |m, l, e| (m == b"member" && l == b"leaf" && e == 7)
                .then(|| (leaf.root.clone(), leaf.block_commitments().len() as u64, 7))) {
            return Err("registered proof rejected".into());
        }
        timings.push(serde_json::json!({"baseline_us":baseline_us,"prepared_us":prepared_us}));
    }
    println!("{}", serde_json::json!({"bytes":replica.len(),"seal_ms":seal_ms,"persist_ms":persist_ms,
        "proofs_equal_and_verified":true,"openings":timings}));
    Ok(())
}
