//! Match response candidates to observed requests by recipient and ID, per host.
//! This observes transport headers, not resolver acceptance or certificate validity.
use commonware_cryptography::PublicKey;
use std::{
    collections::{HashMap, VecDeque},
    sync::Mutex,
    time::{Duration, Instant},
};

const LIMIT: usize = 256;
const RETENTION: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Snapshot {
    pub(crate) requests: u64,
    pub(crate) recipient_targets: u64,
    pub(crate) expected_candidates: u64,
    pub(crate) expected_bytes: u64,
    pub(crate) additional_candidates: u64,
    pub(crate) additional_bytes: u64,
    pub(crate) unmatched_candidates: u64,
    pub(crate) unmatched_bytes: u64,
    pub(crate) evictions: u64,
    pub(crate) expirations: u64,
    pub(crate) untracked_recipients: u64,
    pub(crate) entries: usize,
}

#[derive(Debug)]
struct Entry {
    answered: bool,
}
#[derive(Debug)]
struct State<P: PublicKey> {
    pending: HashMap<(u64, P), Entry>,
    order: VecDeque<((u64, P), Instant)>,
    snapshot: Snapshot,
    limit: usize,
}
#[derive(Debug)]
pub(crate) struct ResolverMatches<P: PublicKey>(Mutex<State<P>>);
impl<P: PublicKey> ResolverMatches<P> {
    pub(crate) fn new() -> Self {
        Self(Mutex::new(State {
            pending: HashMap::new(),
            order: VecDeque::new(),
            snapshot: Snapshot::default(),
            limit: LIMIT,
        }))
    }
    pub(crate) fn snapshot(&self) -> Option<Snapshot> {
        self.0.lock().ok().map(|state| {
            let mut snapshot = state.snapshot;
            snapshot.entries = state.pending.len();
            snapshot
        })
    }
    pub(crate) fn request(&self, recipients: &[P], data: &[u8]) {
        self.request_at(recipients, data, Instant::now());
    }
    fn request_at(&self, recipients: &[P], data: &[u8], now: Instant) {
        // The resolver fetch key is View (u64), so requests are exactly 17 bytes.
        if data.len() != 17 || data[8] != 0 {
            return;
        }
        let id = u64::from_be_bytes(data[..8].try_into().unwrap());
        let Ok(mut state) = self.0.lock() else {
            return;
        };
        state.expire(now);
        state.snapshot.requests += 1;
        state.snapshot.recipient_targets += recipients.len() as u64;
        let limit = state.limit;
        state.snapshot.untracked_recipients += recipients.len().saturating_sub(limit) as u64;
        for peer in recipients.iter().take(limit) {
            let key = (id, peer.clone());
            if state.pending.contains_key(&key) {
                continue;
            }
            if state.pending.len() >= limit {
                let (old, _) = state.order.pop_front().unwrap();
                state.pending.remove(&old);
                state.snapshot.evictions += 1;
            }
            state.pending.insert(key.clone(), Entry { answered: false });
            state.order.push_back((key, now));
        }
    }
    pub(crate) fn response(&self, peer: &P, data: &[u8]) {
        self.response_at(peer, data, Instant::now());
    }
    fn response_at(&self, peer: &P, data: &[u8], now: Instant) {
        // Candidate only: the resolver still does full wire decoding/validation.
        if data.len() < 10 || data[8] != 1 {
            return;
        }
        let id = u64::from_be_bytes(data[..8].try_into().unwrap());
        let Ok(mut state) = self.0.lock() else {
            return;
        };
        state.expire(now);
        let key = (id, peer.clone());
        let prior = state.pending.get_mut(&key).map(|entry| {
            let prior = entry.answered;
            entry.answered = true;
            prior
        });
        match prior {
            Some(false) => {
                state.snapshot.expected_candidates += 1;
                state.snapshot.expected_bytes += data.len() as u64;
            }
            Some(true) => {
                state.snapshot.additional_candidates += 1;
                state.snapshot.additional_bytes += data.len() as u64;
            }
            None => {
                state.snapshot.unmatched_candidates += 1;
                state.snapshot.unmatched_bytes += data.len() as u64;
            }
        }
    }
}
impl<P: PublicKey> State<P> {
    fn expire(&mut self, now: Instant) {
        while self
            .order
            .front()
            .is_some_and(|(_, at)| now.duration_since(*at) >= RETENTION)
        {
            let (key, _) = self.order.pop_front().unwrap();
            self.pending.remove(&key);
            self.snapshot.expirations += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::falcon_base::{FalconPrivateKey, FalconPublicKey};
    use commonware_cryptography::Signer as _;
    use commonware_math::algebra::Random;
    fn peer(seed: u64) -> FalconPublicKey {
        FalconPrivateKey::random(commonware_utils::TestRng::new(seed)).public_key()
    }
    fn request(id: u64) -> Vec<u8> {
        [
            id.to_be_bytes().as_slice(),
            &[0],
            7u64.to_be_bytes().as_slice(),
        ]
        .concat()
    }
    fn response(id: u64) -> Vec<u8> {
        [id.to_be_bytes().as_slice(), &[1, 1, 9]].concat()
    }
    #[test]
    fn matches_sender_and_id_without_cross_host_collisions_or_rejecting_payloads() {
        let diag = ResolverMatches::new();
        let a = peer(1);
        let b = peer(2);
        let now = Instant::now();
        diag.request_at(&[a.clone()], &request(0), now);
        diag.response_at(&b, &response(0), now); // Same ID on another peer is insufficient.
        diag.response_at(&a, &response(1), now);
        diag.response_at(&a, &response(0), now);
        diag.response_at(&a, &response(0), now);
        let other = ResolverMatches::new();
        other.response_at(&a, &response(0), now);
        let stats = diag.snapshot().unwrap();
        assert_eq!(stats.expected_candidates, 1);
        assert_eq!(stats.additional_candidates, 1);
        assert_eq!(stats.unmatched_candidates, 2);
        assert_eq!(other.snapshot().unwrap().unmatched_candidates, 1);
    }
    #[test]
    fn bounds_request_records_and_reports_expiry_without_extending_retries() {
        let diag = ResolverMatches::new();
        let a = peer(1);
        let now = Instant::now();
        diag.0.lock().unwrap().limit = 1;
        diag.request_at(&[a.clone()], &request(0), now);
        diag.request_at(&[a.clone()], &request(1), now);
        assert_eq!(diag.snapshot().unwrap().evictions, 1);
        diag.request_at(&[a.clone()], &request(1), now + Duration::from_secs(59));
        diag.response_at(&a, &response(1), now + RETENTION);
        let stats = diag.snapshot().unwrap();
        assert_eq!(stats.expirations, 1);
        assert_eq!(stats.unmatched_candidates, 1);
        assert_eq!(stats.entries, 0);
    }
}
