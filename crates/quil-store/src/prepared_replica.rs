//! Immutable replica chunks and commitment groups. Publish the small manifest
//! last; interrupted staging is unreachable and removed by epoch eviction.

use std::sync::{Arc, Mutex};
use sha2::{Digest, Sha256};
use quil_crypto::{porep::StorageOpeningReader, sdr::LeafCommitment};
use quil_types::{error::{QuilError, Result}, store::{KvDb, Transaction}};
use super::ReplicaStore;

const MAGIC: &[u8] = b"QREP\x01";
const COMMIT_BYTES: usize = 74;
const BLOCKS_PER_CHUNK: u64 = 32;
const MAX_BYTES: u64 = 8 << 30;

fn invalid() -> QuilError { QuilError::InvalidArgument("invalid prepared storage replica".into()) }

fn epoch_prefix(epoch: u64, kind: u8) -> Vec<u8> {
    let mut key = vec![crate::encoding::STORAGE_REPLICA_PREPARED];
    key.extend_from_slice(&epoch.to_be_bytes());
    key.push(kind);
    key
}

fn leaf_prefix(epoch: u64, kind: u8, id: &[u8]) -> Result<Vec<u8>> {
    let mut key = epoch_prefix(epoch, kind);
    key.extend_from_slice(&u32::try_from(id.len()).map_err(|_| invalid())?.to_be_bytes());
    key.extend_from_slice(id);
    Ok(key)
}

fn upper(mut key: Vec<u8>) -> Vec<u8> {
    while let Some(last) = key.last_mut() {
        if *last != 255 { *last += 1; return key; }
        key.pop();
    }
    unreachable!("prepared prefixes begin below 255")
}

fn put_checked(db: &dyn KvDb, key: &[u8], data: &[u8]) -> Result<()> {
    let mut value = Vec::with_capacity(32 + data.len());
    value.extend_from_slice(&Sha256::digest(data));
    value.extend_from_slice(data);
    db.set(key, &value)
}

/// A manifest pins reads to one immutable generation. Missing chunks or groups
/// are errors; readers never fall back to another replica generation.
pub struct PreparedReplica {
    db: Arc<dyn KvDb>,
    prefix: Vec<u8>,
    len: u64,
    poly: u64,
    root: Vec<u8>,
}

impl PreparedReplica {
    pub fn poly_size(&self) -> u64 { self.poly }

    fn key(&self, kind: u8, level: u32, index: u64) -> Vec<u8> {
        let mut key = self.prefix.clone();
        key.push(kind);
        key.extend_from_slice(&level.to_be_bytes());
        key.extend_from_slice(&index.to_be_bytes());
        key
    }

    fn checked(&self, key: &[u8], expected_len: usize) -> Result<Vec<u8>> {
        let value = self.db.get(key)?.ok_or_else(invalid)?;
        if value.len() != expected_len + 32 || Sha256::digest(&value[32..]).as_slice() != &value[..32] {
            return Err(invalid());
        }
        Ok(value[32..].to_vec())
    }

    fn chunk(&self, index: u64) -> Result<Vec<u8>> {
        let width = self.poly * 32 * BLOCKS_PER_CHUNK;
        let start = index.checked_mul(width).ok_or_else(invalid)?;
        if start >= self.len { return Err(invalid()); }
        self.checked(&self.key(0, 0, index), (self.len - start).min(width) as usize)
    }

    pub(super) fn read_all(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.len as usize);
        let width = self.poly * 32 * BLOCKS_PER_CHUNK;
        for index in 0..self.len.div_ceil(width) { out.extend(self.chunk(index)?); }
        Ok(out)
    }
}

impl StorageOpeningReader for PreparedReplica {
    fn replica_len(&self) -> u64 { self.len }
    fn root(&self) -> &[u8] { &self.root }

    fn block(&self, index: u64) -> Result<Vec<u8>> {
        let width = self.poly * 32;
        if index >= self.len.div_ceil(width).max(1) { return Err(invalid()); }
        if self.len == 0 { return Ok(Vec::new()); }
        let chunk = self.chunk(index / BLOCKS_PER_CHUNK)?;
        let start = (index % BLOCKS_PER_CHUNK * width) as usize;
        let end = (start + width as usize).min(chunk.len());
        Ok(chunk[start..end].to_vec())
    }

    fn group(&self, level: u32, index: u64) -> Result<Vec<Vec<u8>>> {
        let mut count = self.len.div_ceil(self.poly * 32).max(1);
        for _ in 0..level {
            if count <= 1 { return Err(invalid()); }
            count = count.div_ceil(self.poly);
        }
        let start = index.checked_mul(self.poly).ok_or_else(invalid)?;
        if start >= count { return Err(invalid()); }
        let len = (count - start).min(self.poly) as usize * COMMIT_BYTES;
        Ok(self.checked(&self.key(1, level, index), len)?
            .chunks_exact(COMMIT_BYTES).map(<[u8]>::to_vec).collect())
    }
}

impl ReplicaStore {
    // Serialize publication/retirement even across independently constructed
    // handles to one backing database. Sealing and all reads stay concurrent;
    // this lock covers only persistent staging and its atomic publication.
    pub(super) fn writer() -> &'static Mutex<()> {
        static WRITER: Mutex<()> = Mutex::new(());
        &WRITER
    }

    /// Persist the already computed commitment with bounded replica chunks.
    /// A publication atomically replaces the legacy value. Older binaries see
    /// this replica as absent, rather than interpreting a new format as bytes.
    pub fn put_prepared(&self, epoch: u64, id: &[u8], replica: &[u8], leaf: &LeafCommitment) -> Result<()> {
        let _guard = Self::writer().lock().map_err(|_| invalid())?;
        let poly = leaf.poly_size;
        if !(2..=256).contains(&poly) || !poly.is_power_of_two() || replica.len() as u64 > MAX_BYTES
            || leaf.root.len() != COMMIT_BYTES { return Err(invalid()); }
        let mut count = (replica.len() as u64).div_ceil(poly * 32).max(1);
        let mut expected_levels = 1;
        let mut remaining = count;
        while remaining > 1 { remaining = remaining.div_ceil(poly); expected_levels += 1; }
        if leaf.levels.len() != expected_levels { return Err(invalid()); }
        for level in &leaf.levels {
            if level.len() as u64 != count || level.iter().any(|c| c.len() != COMMIT_BYTES) {
                return Err(invalid());
            }
            count = count.div_ceil(poly);
        }
        if leaf.levels.last().and_then(|l| l.first()) != Some(&leaf.root) { return Err(invalid()); }
        let mut digest = Sha256::new();
        digest.update(poly.to_be_bytes()); digest.update(replica); digest.update(&leaf.root);
        let generation = digest.finalize();
        let mut prefix = leaf_prefix(epoch, 1, id)?;
        prefix.extend_from_slice(&generation);
        let prepared = PreparedReplica { db: self.db.clone(), prefix, len: replica.len() as u64,
            poly, root: leaf.root.clone() };
        let previous = self.prepared(epoch, id)?;
        let stage = (|| -> Result<()> {
            let width = (poly * 32 * BLOCKS_PER_CHUNK) as usize;
            for (index, chunk) in replica.chunks(width).enumerate() {
                put_checked(self.db.as_ref(), &prepared.key(0, 0, index as u64), chunk)?;
            }
            for (level, commits) in leaf.levels.iter().enumerate() {
                for (index, group) in commits.chunks(poly as usize).enumerate() {
                    put_checked(self.db.as_ref(), &prepared.key(1, level as u32, index as u64), &group.concat())?;
                }
            }
            Ok(())
        })();
        if let Err(error) = stage {
            // Never erase the currently published generation on a failed
            // same-generation repair. Other incomplete staging is disposable.
            if previous.as_ref().is_none_or(|old| old.prefix != prepared.prefix) {
                self.db.delete_range(&prepared.prefix, &upper(prepared.prefix.clone()))?;
            }
            return Err(error);
        }
        let mut manifest = MAGIC.to_vec();
        manifest.extend_from_slice(&poly.to_be_bytes());
        manifest.extend_from_slice(&(replica.len() as u64).to_be_bytes());
        manifest.extend_from_slice(&generation);
        manifest.extend_from_slice(&leaf.root);
        let batch = self.db.new_batch(false)?;
        batch.set(&leaf_prefix(epoch, 0, id)?, &manifest)?;
        batch.delete(&super::replica_key(epoch, id))?;
        let data_prefix = leaf_prefix(epoch, 1, id)?;
        batch.delete_range(&data_prefix, &prepared.prefix)?;
        let after = upper(prepared.prefix.clone());
        let end = upper(data_prefix);
        if after < end { batch.delete_range(&after, &end)?; }
        batch.commit()
    }

    pub fn prepared(&self, epoch: u64, id: &[u8]) -> Result<Option<PreparedReplica>> {
        let Some(value) = self.db.get(&leaf_prefix(epoch, 0, id)?)? else { return Ok(None); };
        if value.len() != MAGIC.len() + 16 + 32 + COMMIT_BYTES || !value.starts_with(MAGIC) {
            return Err(invalid());
        }
        let value = &value[MAGIC.len()..];
        let poly = u64::from_be_bytes(value[..8].try_into().unwrap());
        let len = u64::from_be_bytes(value[8..16].try_into().unwrap());
        if !(2..=256).contains(&poly) || !poly.is_power_of_two() || len > MAX_BYTES { return Err(invalid()); }
        let mut prefix = leaf_prefix(epoch, 1, id)?;
        prefix.extend_from_slice(&value[16..48]);
        Ok(Some(PreparedReplica { db: self.db.clone(), prefix, len, poly, root: value[48..].to_vec() }))
    }

    pub(super) fn clear_prepared(&self, batch: &dyn Transaction, epoch: u64, id: &[u8]) -> Result<()> {
        batch.delete(&leaf_prefix(epoch, 0, id)?)?;
        let prefix = leaf_prefix(epoch, 1, id)?;
        batch.delete_range(&prefix, &upper(prefix.clone()))
    }

    pub(super) fn for_each_prepared_in_epoch(&self, epoch: u64, f: &mut impl FnMut(Vec<u8>, Vec<u8>)) -> Result<()> {
        let prefix = epoch_prefix(epoch, 0);
        let mut iter = self.db.new_iter(&prefix, &upper(prefix.clone()))?;
        let result = (|| {
            let mut ok = iter.first();
            while ok {
                let key = iter.key();
                if key.len() < 14 { return Err(invalid()); }
                let len = u32::from_be_bytes(key[10..14].try_into().unwrap()) as usize;
                if key.len() != 14 + len { return Err(invalid()); }
                let id = key[14..].to_vec();
                let replica = self.prepared(epoch, &id)?.ok_or_else(invalid)?.read_all()?;
                f(id, replica);
                ok = iter.next();
            }
            Ok(())
        })();
        let close = iter.close();
        result.and(close)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
    use quil_types::store::Iterator as StoreIterator;

    struct Metered {
        inner: Arc<crate::RocksDb>,
        bytes: AtomicUsize,
        fail_after: AtomicUsize,
    }
    impl KvDb for Metered {
        fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
            let value = self.inner.get(key)?;
            self.bytes.fetch_add(value.as_ref().map_or(0, Vec::len), SeqCst);
            Ok(value)
        }
        fn set(&self, key: &[u8], value: &[u8]) -> Result<()> {
            if self.fail_after.fetch_update(SeqCst, SeqCst, |n| n.checked_sub(1)) == Ok(1) {
                return Err(QuilError::Store("injected replica staging failure".into()));
            }
            self.inner.set(key, value)
        }
        fn delete(&self, key: &[u8]) -> Result<()> { self.inner.delete(key) }
        fn new_batch(&self, indexed: bool) -> Result<Box<dyn Transaction>> { self.inner.new_batch(indexed) }
        fn new_iter(&self, lo: &[u8], hi: &[u8]) -> Result<Box<dyn StoreIterator>> { self.inner.new_iter(lo, hi) }
        fn compact(&self, lo: &[u8], hi: &[u8], parallel: bool) -> Result<()> { self.inner.compact(lo, hi, parallel) }
        fn compact_all(&self) -> Result<()> { self.inner.compact_all() }
        fn close(&self) -> Result<()> { self.inner.close() }
        fn delete_range(&self, lo: &[u8], hi: &[u8]) -> Result<()> { self.inner.delete_range(lo, hi) }
    }

    fn fixture() -> (ReplicaStore, Arc<Metered>) {
        quil_crypto::init();
        let db = Arc::new(Metered { inner: Arc::new(crate::RocksDb::open_in_memory().unwrap()),
            bytes: AtomicUsize::new(0), fail_after: AtomicUsize::new(0) });
        (ReplicaStore::new(db.clone()), db)
    }

    #[test]
    fn prepared_openings_match_original_proofs_with_bounded_reads() {
        let (store, db) = fixture();
        // Multiple commitment levels, several data chunks, and a partial block.
        let replica: Vec<u8> = (0..131 * 2048 + 19).map(|i| (i * 37) as u8).collect();
        let leaf = quil_crypto::sdr::commit_leaf(&replica, 64);
        store.put_prepared(7, b"leaf", &replica, &leaf).unwrap();
        db.bytes.store(0, SeqCst);
        assert_eq!(store.get(7, b"leaf").unwrap().unwrap(), replica);
        assert!(db.bytes.load(SeqCst) >= replica.len(), "the full-read control must read the whole replica");
        assert!(db.inner.get(&super::super::replica_key(7, b"leaf")).unwrap().is_none());
        for beacon in 0..4 {
            let rho = [beacon; 32];
            let expected = quil_crypto::porep::build_storage_opening(&replica, &leaf, b"leaf", 7, b"member", 0, &rho, 64);
            db.bytes.store(0, SeqCst);
            let prepared = store.prepared(7, b"leaf").unwrap().unwrap();
            let actual = quil_crypto::porep::build_storage_opening_from_reader(&prepared, b"leaf", 7, b"member", 0, &rho, 64).unwrap();
            assert_eq!(actual.to_proto(), expected.to_proto());
            assert!(db.bytes.load(SeqCst) < 80 * 1024, "one opening must not read the full replica");
            let (att, root) = quil_crypto::porep::build_frame_storage_attestation(&[actual], 100, &rho, &[], 64);
            assert!(quil_crypto::porep::verify_frame_storage_attestation_registered(
                &root, &att, 100, &rho, &[], 64, 7,
                |m, l, e| (m == b"member" && l == b"leaf" && e == 7).then(|| (leaf.root.clone(), leaf.block_commitments().len() as u64, 7))));
        }
    }

    #[test]
    fn prepared_empty_and_partial_replicas_survive_reopen() {
        quil_crypto::init();
        let dir = tempfile::tempdir().unwrap();
        for replica in [vec![], vec![3; 19], vec![5; 4099]] {
            let leaf = quil_crypto::sdr::commit_leaf(&replica, 64);
            {
                let store = ReplicaStore::new(Arc::new(crate::RocksDb::open(dir.path()).unwrap()));
                store.put_prepared(3, b"leaf", &replica, &leaf).unwrap();
            }
            let store = ReplicaStore::new(Arc::new(crate::RocksDb::open(dir.path()).unwrap()));
            assert_eq!(store.get(3, b"leaf").unwrap(), Some(replica.clone()));
            let prepared = store.prepared(3, b"leaf").unwrap().unwrap();
            let got = quil_crypto::porep::build_storage_opening_from_reader(&prepared, b"leaf", 3, b"member", 0, &[1; 32], 64).unwrap();
            let expected = quil_crypto::porep::build_storage_opening(&replica, &leaf, b"leaf", 3, b"member", 0, &[1; 32], 64);
            assert_eq!(got.to_proto(), expected.to_proto());
        }
    }

    #[test]
    fn interrupted_staging_preserves_published_generation_and_epoch_eviction_removes_orphans() {
        let (store, db) = fixture();
        let old = vec![3; 4096]; let new = vec![7; 128 * 1024];
        let leaf = quil_crypto::sdr::commit_leaf(&old, 64);
        store.put_prepared(4, b"leaf", &old, &leaf).unwrap();
        let next = quil_crypto::sdr::commit_leaf(&new, 64);
        db.fail_after.store(2, SeqCst);
        assert!(store.put_prepared(4, b"leaf", &new, &next).is_err());
        assert_eq!(store.get(4, b"leaf").unwrap(), Some(old.clone()));
        store.put(5, b"legacy", &old).unwrap();
        store.put_prepared(5, b"leaf", &old, &leaf).unwrap();
        store.evict_below_epoch(5).unwrap();
        assert!(store.get(4, b"leaf").unwrap().is_none());
        let lo = epoch_prefix(4, 0); let hi = epoch_prefix(5, 0);
        let mut iter = db.inner.new_iter(&lo, &hi).unwrap();
        assert!(!iter.first(), "failed staging chunks must be evicted too"); iter.close().unwrap();
        let mut seen = Vec::new(); store.for_each_in_epoch(5, |id, data| seen.push((id, data))).unwrap();
        seen.sort(); assert_eq!(seen, vec![(b"leaf".to_vec(), old.clone()), (b"legacy".to_vec(), old)]);
    }

    #[test]
    fn overwrite_delete_and_corruption_never_reuse_stale_commitments() {
        let (store, db) = fixture(); let replica = vec![9; 5000];
        let leaf = quil_crypto::sdr::commit_leaf(&replica, 64);
        store.put_prepared(2, b"leaf", &replica, &leaf).unwrap();
        let old = store.prepared(2, b"leaf").unwrap().unwrap();
        store.put(2, b"leaf", b"new legacy bytes").unwrap();
        assert!(store.prepared(2, b"leaf").unwrap().is_none());
        assert!(old.block(0).is_err());
        assert_eq!(store.get(2, b"leaf").unwrap().as_deref(), Some(b"new legacy bytes".as_slice()));
        store.put_prepared(2, b"leaf", &replica, &leaf).unwrap();
        let prepared = store.prepared(2, b"leaf").unwrap().unwrap();
        db.inner.set(&prepared.key(0, 0, 0), b"torn block").unwrap();
        assert!(quil_crypto::porep::build_storage_opening_from_reader(&prepared, b"leaf", 2, b"member", 0, &[1; 32], 64).is_err());
        // Even a well-checksummed stale group must fail the commitment-path check.
        store.put_prepared(2, b"leaf", &replica, &leaf).unwrap();
        put_checked(db.inner.as_ref(), &prepared.key(1, 0, 0), &vec![0; 3 * COMMIT_BYTES]).unwrap();
        assert!(quil_crypto::porep::build_storage_opening_from_reader(&prepared, b"leaf", 2, b"member", 0, &[1; 32], 64).is_err());
        store.delete(2, b"leaf").unwrap();
        assert!(store.get(2, b"leaf").unwrap().is_none());
        db.inner.set(&leaf_prefix(2, 0, b"leaf").unwrap(), MAGIC).unwrap();
        assert!(store.prepared(2, b"leaf").is_err());
    }

    #[test]
    fn publication_retires_superseded_generations_without_mixing_readers() {
        let (store, _) = fixture();
        let old = vec![1; 4096]; let new = vec![2; 4096];
        let leaf = quil_crypto::sdr::commit_leaf(&old, 64);
        store.put_prepared(3, b"leaf", &old, &leaf).unwrap();
        let old_reader = store.prepared(3, b"leaf").unwrap().unwrap();
        let leaf = quil_crypto::sdr::commit_leaf(&new, 64);
        store.put_prepared(3, b"leaf", &new, &leaf).unwrap();
        assert_eq!(store.get(3, b"leaf").unwrap(), Some(new));
        assert!(old_reader.block(0).is_err(), "an old reader must not mix in the new generation");
        assert!(old_reader.db.get(&old_reader.key(1, 0, 0)).unwrap().is_none(),
            "superseded commitment data must be retired at publication");
    }
}
