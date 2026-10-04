//! Opt-in observation of app-shard consensus gossip, never a delivery gate.
//!
//! Labels describe channels and observation stages, not peers or shards.
//! Fingerprints retain the publisher and topic internally, strip only the
//! transport nonce, and expire without retaining message bodies.

use std::collections::{HashMap, VecDeque};

use prometheus_client::{
    encoding::EncodeLabelSet,
    metrics::{counter::Counter, family::Family, gauge::Gauge},
    registry::Registry,
};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

use libp2p::PeerId;

pub(crate) struct TrafficMessage<'a> {
    pub(crate) source: Option<&'a PeerId>,
    pub(crate) topic: &'a [u8],
    pub(crate) data: &'a [u8],
}

const MAX_ENTRIES: usize = 32_768;
const RETENTION: Duration = Duration::from_secs(60);
pub(crate) const MAX_BODY_BYTES: usize = 256 * 1024;
const HASH_BYTES_PER_SECOND: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct TrafficLabels {
    stage: &'static str,
    channel: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct RepeatLabels {
    stage: &'static str,
    channel: &'static str,
    observation: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct SkipLabels {
    stage: &'static str,
    channel: &'static str,
    reason: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct OutcomeLabels {
    stage: &'static str,
    channel: &'static str,
    outcome: &'static str,
}

struct Seen {
    nonce: Option<[u8; 8]>,
}

pub(crate) struct CwTrafficDiagnostics {
    resolver: crate::resolver_traffic_diagnostics::ResolverTrafficDiagnostics,
    messages: Family<TrafficLabels, Counter>,
    payload_bytes: Family<TrafficLabels, Counter>,
    observations: Family<RepeatLabels, Counter>,
    body_bytes: Family<RepeatLabels, Counter>,
    skipped: Family<SkipLabels, Counter>,
    skipped_bytes: Family<SkipLabels, Counter>,
    outcomes: Family<OutcomeLabels, Counter>,
    cache_entries: Gauge,
    evictions: Counter,
    expirations: Counter,
    seen: HashMap<[u8; 32], Seen>,
    insertion_order: VecDeque<([u8; 32], Instant)>,
    max_entries: usize,
    budget_start: Instant,
    budget_remaining: usize,
}

impl CwTrafficDiagnostics {
    #[cfg(test)]
    pub(crate) fn for_test(registry: &mut Registry) -> Self {
        Self::new(registry, MAX_ENTRIES, Instant::now())
    }

    pub(crate) fn from_env(registry: &mut Registry) -> Option<Self> {
        if std::env::var("QUIL_DIAG_CW_TRAFFIC").as_deref() != Ok("1") {
            return None;
        }
        tracing::info!(
            max_entries = MAX_ENTRIES,
            retention_secs = RETENTION.as_secs(),
            max_body_bytes = MAX_BODY_BYTES,
            hash_bytes_per_second = HASH_BYTES_PER_SECOND,
            "bounded CW traffic diagnostics enabled"
        );
        Some(Self::new(registry, MAX_ENTRIES, Instant::now()))
    }

    fn new(registry: &mut Registry, max_entries: usize, now: Instant) -> Self {
        macro_rules! family {
            ($name:literal, $help:literal) => {{
                let value = Family::default();
                registry.register($name, $help, value.clone());
                value
            }};
        }
        let messages = family!(
            "cw_traffic_messages",
            "CW messages at the wrapper; received messages have passed gossip-ID deduplication"
        );
        let payload_bytes = family!(
            "cw_traffic_payload_bytes",
            "CW payload bytes observed, not TCP wire bytes"
        );
        let observations = family!("cw_traffic_body_observations", "Bounded same-author/topic/channel body observations; nonce changed compares the last observed nonce");
        let body_bytes = family!(
            "cw_traffic_body_bytes",
            "CW body bytes classified after stripping transport framing"
        );
        let skipped = family!(
            "cw_traffic_fingerprint_skipped",
            "Messages excluded from bounded body fingerprinting"
        );
        let skipped_bytes = family!(
            "cw_traffic_fingerprint_skipped_bytes",
            "Body bytes excluded from fingerprinting; malformed messages count payload bytes"
        );
        let outcomes = family!(
            "cw_traffic_outcomes",
            "Publication results and wrapper validation outcomes, not consensus quorum validation"
        );
        let cache_entries = Gauge::default();
        registry.register(
            "cw_traffic_cache_entries",
            "Retained fingerprints, including expired entries until the next observation",
            cache_entries.clone(),
        );
        let evictions = Counter::default();
        registry.register(
            "cw_traffic_cache_evictions",
            "Fingerprints evicted at the capacity limit",
            evictions.clone(),
        );
        let expirations = Counter::default();
        registry.register(
            "cw_traffic_cache_expirations",
            "Fingerprints expired at the retention limit",
            expirations.clone(),
        );
        Self {
            resolver: crate::resolver_traffic_diagnostics::ResolverTrafficDiagnostics::new(
                registry,
            ),
            messages,
            payload_bytes,
            observations,
            body_bytes,
            skipped,
            skipped_bytes,
            outcomes,
            cache_entries,
            evictions,
            expirations,
            seen: HashMap::new(),
            insertion_order: VecDeque::new(),
            max_entries,
            budget_start: now,
            budget_remaining: HASH_BYTES_PER_SECOND,
        }
    }

    pub(crate) fn observe(
        &mut self,
        stage: &'static str,
        message: &TrafficMessage<'_>,
        bytes: usize,
    ) {
        self.observe_at(stage, message, bytes, Instant::now());
    }

    pub(crate) fn outcome(
        &mut self,
        stage: &'static str,
        channel: &'static str,
        outcome: &'static str,
    ) {
        self.outcomes
            .get_or_create(&OutcomeLabels {
                stage,
                channel,
                outcome,
            })
            .inc();
    }

    fn observe_at(
        &mut self,
        stage: &'static str,
        message: &TrafficMessage<'_>,
        bytes: usize,
        now: Instant,
    ) {
        if message.topic.len() != 33 || message.topic[0] != 1 {
            return;
        }
        let parsed = split_payload(&message.data);
        let channel = parsed
            .as_ref()
            .map_or("unknown", |(channel, _, _)| *channel);
        let labels = TrafficLabels { stage, channel };
        self.messages.get_or_create(&labels).inc();
        self.payload_bytes
            .get_or_create(&labels)
            .inc_by(bytes as u64);

        while self
            .insertion_order
            .front()
            .is_some_and(|(_, inserted)| now.duration_since(*inserted) >= RETENTION)
        {
            let (key, _) = self.insertion_order.pop_front().expect("front exists");
            self.seen.remove(&key);
            self.expirations.inc();
        }
        self.cache_entries.set(self.seen.len() as i64);
        let Some((channel, nonce, body)) = parsed else {
            self.skip(stage, channel, "malformed", message.data.len());
            return;
        };
        if now.duration_since(self.budget_start) >= Duration::from_secs(1) {
            self.budget_start = now;
            self.budget_remaining = HASH_BYTES_PER_SECOND;
        }
        if channel == "resolver" {
            self.resolver
                .observe(stage, message, body, now, &mut self.budget_remaining);
        }
        let Some(author) = message.source else {
            self.skip(stage, channel, "missing_author", body.len());
            return;
        };
        if body.len() > MAX_BODY_BYTES {
            self.skip(stage, channel, "oversize", body.len());
            return;
        }
        // Charge fixed fields too: empty bodies cannot bypass the CPU budget.
        let author = author.to_bytes();
        let cost = body.len().saturating_add(author.len()).saturating_add(128);
        if cost > self.budget_remaining {
            self.skip(stage, channel, "hash_budget", body.len());
            return;
        }
        self.budget_remaining -= cost;
        let mut hash = Sha256::new();
        hash.update(b"cw-traffic-body-v1");
        hash.update((stage.len() as u64).to_be_bytes());
        hash.update(stage.as_bytes());
        hash.update((author.len() as u64).to_be_bytes());
        hash.update(author);
        hash.update(message.topic);
        hash.update(channel.as_bytes());
        hash.update(body);
        let key: [u8; 32] = hash.finalize().into();
        let observation = if let Some(previous) = self.seen.get_mut(&key) {
            let observation = if nonce != previous.nonce {
                "nonce_changed_repeat"
            } else if nonce.is_some() {
                "same_nonce_repeat"
            } else {
                "legacy_repeat"
            };
            previous.nonce = nonce;
            observation
        } else {
            if self.seen.len() >= self.max_entries {
                let (oldest, _) = self.insertion_order.pop_front().expect("cache is full");
                self.seen.remove(&oldest);
                self.evictions.inc();
            }
            self.seen.insert(key, Seen { nonce });
            self.insertion_order.push_back((key, now));
            self.cache_entries.set(self.seen.len() as i64);
            "first_seen"
        };
        let labels = RepeatLabels {
            stage,
            channel,
            observation,
        };
        self.observations.get_or_create(&labels).inc();
        self.body_bytes
            .get_or_create(&labels)
            .inc_by(body.len() as u64);
    }

    fn skip(&self, stage: &'static str, channel: &'static str, reason: &'static str, bytes: usize) {
        let labels = SkipLabels {
            stage,
            channel,
            reason,
        };
        self.skipped.get_or_create(&labels).inc();
        self.skipped_bytes
            .get_or_create(&labels)
            .inc_by(bytes as u64);
    }
}

fn split_payload(data: &[u8]) -> Option<(&'static str, Option<[u8; 8]>, &[u8])> {
    let (&first, rest) = data.split_first()?;
    let channel = match first & 0x7f {
        0 => "vote",
        1 => "certificate",
        2 => "resolver",
        3 => "block",
        _ => return None,
    };
    if first & 0x80 == 0 {
        Some((channel, None, rest))
    } else {
        Some((
            channel,
            Some(rest.get(..8)?.try_into().ok()?),
            rest.get(8..)?,
        ))
    }
}

pub(crate) fn channel(topic: &[u8], data: &[u8]) -> Option<&'static str> {
    if topic.len() != 33 || topic[0] != 1 {
        return None;
    }
    Some(split_payload(data).map_or("unknown", |(channel, _, _)| channel))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Clone)]
    struct OwnedMessage {
        source: Option<PeerId>,
        data: Vec<u8>,
        topic: Vec<u8>,
    }
    impl OwnedMessage {
        fn borrowed(&self) -> TrafficMessage<'_> {
            TrafficMessage {
                source: self.source.as_ref(),
                topic: &self.topic,
                data: &self.data,
            }
        }
    }

    fn message(channel: u8, nonce: Option<u64>, body: &[u8]) -> OwnedMessage {
        let mut topic = vec![0; 33];
        topic[0] = 1;
        topic[1] = 4;
        let mut data = vec![channel | if nonce.is_some() { 0x80 } else { 0 }];
        if let Some(nonce) = nonce {
            data.extend_from_slice(&nonce.to_be_bytes());
        }
        data.extend_from_slice(body);
        OwnedMessage {
            source: Some(PeerId::random()),
            data,
            topic,
        }
    }

    fn count(metrics: &CwTrafficDiagnostics, observation: &'static str) -> u64 {
        metrics
            .observations
            .get_or_create(&RepeatLabels {
                stage: "receive_unique",
                channel: "vote",
                observation,
            })
            .get()
    }

    #[test]
    fn distinguishes_changed_nonces_from_relayed_transmissions_and_legacy_repeats() {
        let now = Instant::now();
        let mut registry = Registry::default();
        let mut metrics = CwTrafficDiagnostics::new(&mut registry, 8, now);
        let first = message(0, Some(1), b"vote");
        let mut retry = first.clone();
        retry.data[1..9].copy_from_slice(&2u64.to_be_bytes());
        for m in [&first, &first, &retry] {
            metrics.observe_at("receive_unique", &m.borrowed(), 100, now);
        }
        assert_eq!(count(&metrics, "first_seen"), 1);
        assert_eq!(count(&metrics, "same_nonce_repeat"), 1);
        assert_eq!(count(&metrics, "nonce_changed_repeat"), 1);
        let mut legacy = first.clone();
        legacy.data = vec![0];
        legacy.data.extend_from_slice(b"vote");
        metrics.observe_at("receive_unique", &legacy.borrowed(), 90, now);
        metrics.observe_at("receive_unique", &legacy.borrowed(), 90, now);
        assert_eq!(count(&metrics, "legacy_repeat"), 1);
        assert_eq!(
            first.data,
            [vec![0x80], 1u64.to_be_bytes().to_vec(), b"vote".to_vec()].concat()
        );
    }

    #[test]
    fn body_identity_preserves_author_topic_channel_and_observation_stage() {
        let now = Instant::now();
        let mut registry = Registry::default();
        let mut metrics = CwTrafficDiagnostics::new(&mut registry, 8, now);
        let first = message(0, Some(1), b"same bytes");
        let mut author = first.clone();
        author.source = Some(PeerId::random());
        let mut topic = first.clone();
        let mut t = topic.topic.as_slice().to_vec();
        t[2] = 8;
        topic.topic = t;
        let mut channel = first.clone();
        channel.data[0] = 0x81;
        for m in [&first, &author, &topic, &channel] {
            metrics.observe_at("receive_unique", &m.borrowed(), 100, now);
        }
        metrics.observe_at("publish_attempt", &first.borrowed(), 100, now);

        assert_eq!(metrics.seen.len(), 5);
        assert_eq!(count(&metrics, "first_seen"), 3);
    }

    #[test]
    fn cache_and_hash_work_are_bounded_with_explicit_coverage_counters() {
        let now = Instant::now();
        let mut registry = Registry::default();
        let mut metrics = CwTrafficDiagnostics::new(&mut registry, 2, now);
        let first = message(0, Some(1), b"first");
        for body in [
            b"first".as_slice(),
            b"second".as_slice(),
            b"third".as_slice(),
        ] {
            let mut m = first.clone();
            m.data.truncate(9);
            m.data.extend_from_slice(body);
            metrics.observe_at("receive_unique", &m.borrowed(), 100, now);
        }
        assert_eq!(metrics.seen.len(), 2);
        assert_eq!(metrics.evictions.get(), 1);
        metrics.observe_at("receive_unique", &first.borrowed(), 100, now + RETENTION);
        assert_eq!(metrics.expirations.get(), 2);
        assert_eq!(metrics.seen.len(), 1);
        metrics.budget_remaining = 0;
        metrics.observe_at("receive_unique", &first.borrowed(), 100, now + RETENTION);
        assert_eq!(
            metrics
                .skipped
                .get_or_create(&SkipLabels {
                    stage: "receive_unique",
                    channel: "vote",
                    reason: "hash_budget"
                })
                .get(),
            1
        );
        metrics.observe_at(
            "receive_unique",
            &first.borrowed(),
            100,
            now + RETENTION + Duration::from_secs(1),
        );
        assert_eq!(metrics.seen.len(), 1);
        let mut oversized = first.clone();
        oversized.data.resize(MAX_BODY_BYTES + 10, 0);
        metrics.observe_at(
            "receive_unique",
            &oversized.borrowed(),
            100,
            now + RETENTION + Duration::from_secs(1),
        );
        assert_eq!(
            metrics
                .skipped
                .get_or_create(&SkipLabels {
                    stage: "receive_unique",
                    channel: "vote",
                    reason: "oversize"
                })
                .get(),
            1
        );
        let mut malformed = first.clone();
        malformed.data = vec![0x80, 0];
        metrics.observe_at(
            "receive_unique",
            &malformed.borrowed(),
            100,
            now + RETENTION + Duration::from_secs(1),
        );
        assert_eq!(
            metrics
                .skipped
                .get_or_create(&SkipLabels {
                    stage: "receive_unique",
                    channel: "unknown",
                    reason: "malformed"
                })
                .get(),
            1
        );
    }

    #[test]
    fn exported_labels_are_fixed_and_never_contain_authors_topics_or_bodies() {
        let now = Instant::now();
        let mut registry = Registry::default();
        let mut metrics = CwTrafficDiagnostics::new(&mut registry, 8, now);
        for channel in 0..4 {
            metrics.observe_at(
                "receive_unique",
                &message(channel, Some(1), b"private payload").borrowed(),
                100,
                now,
            );
        }
        let mut out = String::new();
        prometheus_client::encoding::text::encode(&mut out, &registry).unwrap();
        assert!(out.contains("channel=\"resolver\""));
        assert!(out.contains("stage=\"receive_unique\""));
        assert!(!out.contains("hash="));
        assert!(!out.contains("author="));
        assert!(!out.contains("private payload"));
    }
}
