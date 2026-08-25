//! Trait for syncing the global prover tree from archives.
//!
//! Workers need to sync the prover tree to resolve leader rotation,
//! verify FrameHeaders, and attribute shard work. In Go this is
//! `AppConsensusEngine.performBlockingGlobalHypersync` which calls
//! `HyperSyncSelf` against the master/archive. The Rust port can't
//! call `quil-rpc` from `quil-engine` (circular dep), so the trait
//! lives here and the implementation lives in `quil-node`.

use async_trait::async_trait;
use quil_types::error::Result;
use quil_types::proto::global::AppShardFrame;

/// Syncs the global prover tree (vertex-adds set for the global
/// intrinsic address) from an archive. Returns `true` if the
/// locally-recomputed root matches `expected_root` after sync.
///
/// Implementations should:
/// 1. Connect to an archive endpoint (mTLS)
/// 2. Pull the prover tree via `ensure_prover_tree_incremental`
/// with `expected_root` pinned
/// 3. Return whether the final root matches
#[async_trait]
pub trait ProverTreeSyncer: Send + Sync {
    /// Sync the global prover tree, pinning EACH phase to `expected_roots[phase]`
    /// — `[prover_tree_commitment (phase 0), prover_tree_aux_roots (1,2,3)]` from
    /// the global header (audit #5: all four phases anchored). Empty slice ⇒
    /// trust the peer (bootstrap). Returns `Ok(true)` if post-sync roots match,
    /// `Ok(false)` if the sync completed but roots still diverge, `Err` on failure.
    async fn sync_prover_tree(&self, expected_roots: &[Vec<u8>]) -> Result<bool>;

    /// Sync a specific app-shard's subtrees from an archive, pinning EACH of
    /// the four phases to `expected_roots[phase]` — the finalized header's
    /// `state_roots` (audit #5: all four phases anchored, not just vertex-adds).
    /// Used to catch a shard's CRDT up after a frame gap / restart / late-join
    /// (step 4). `filter` is the shard filter; the impl derives the `ShardKey`.
    /// An empty entry (or empty slice) trusts the peer for that phase
    /// (bootstrap). Default is a no-op (`Ok(false)`) for syncers without shard
    /// sync.
    async fn sync_shard_tree(&self, _filter: &[u8], _expected_roots: &[Vec<u8>]) -> Result<bool> {
        Ok(false)
    }

    /// As [`Self::sync_shard_tree`], but pins the request to `endpoint` when an
    /// implementation supports it. Bootstrap uses this to ensure that an anchor
    /// frame and its authenticated forest roots come from the same archive.
    async fn sync_shard_tree_at_endpoint(
        &self,
        filter: &[u8],
        expected_roots: &[Vec<u8>],
        _endpoint: Option<&str>,
    ) -> Result<bool> {
        self.sync_shard_tree(filter, expected_roots).await
    }

    /// Fetch an app-shard frame from an archive. `frame_number == 0` requests
    /// the latest frame and is used to seed an empty worker's clock lineage.
    async fn get_app_shard_frame(
        &self,
        _filter: &[u8],
        _frame_number: u64,
    ) -> Result<Option<AppShardFrame>> {
        Ok(None)
    }

    /// Fetch an app-shard frame, optionally pinning to `endpoint`. Returns the
    /// endpoint actually used when the implementation can report it.
    async fn get_app_shard_frame_at_endpoint(
        &self,
        filter: &[u8],
        frame_number: u64,
        _endpoint: Option<&str>,
    ) -> Result<(Option<AppShardFrame>, Option<String>)> {
        Ok((self.get_app_shard_frame(filter, frame_number).await?, None))
    }
}
