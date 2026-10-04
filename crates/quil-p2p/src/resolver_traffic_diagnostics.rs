//! Bounded, observational resolver wire/content accounting. Never gates delivery.
use crate::cw_traffic_diagnostics::{TrafficMessage, MAX_BODY_BYTES};
use prometheus_client::{
    encoding::EncodeLabelSet,
    metrics::{counter::Counter, family::Family, gauge::Gauge},
    registry::Registry,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};

const MAX_RESPONSES: usize = 8_192;
const RETENTION: Duration = Duration::from_secs(60);

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct KindLabels {
    stage: &'static str,
    kind: &'static str,
}
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ContentLabels {
    stage: &'static str,
    observation: &'static str,
}
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct SkipLabels {
    stage: &'static str,
    reason: &'static str,
}
struct Seen {
    author: [u8; 32],
    id: u64,
}

pub(crate) struct ResolverTrafficDiagnostics {
    messages: Family<KindLabels, Counter>,
    bytes: Family<KindLabels, Counter>,
    content: Family<ContentLabels, Counter>,
    content_bytes: Family<ContentLabels, Counter>,
    skipped: Family<SkipLabels, Counter>,
    skipped_bytes: Family<SkipLabels, Counter>,
    entries: Gauge,
    evictions: Counter,
    expirations: Counter,
    seen: HashMap<[u8; 32], Seen>,
    order: VecDeque<([u8; 32], Instant)>,
    limit: usize,
}

impl ResolverTrafficDiagnostics {
    pub(crate) fn new(registry: &mut Registry) -> Self {
        macro_rules! family {
            ($name:literal, $help:literal) => {{
                let value = Family::default();
                registry.register($name, $help, value.clone());
                value
            }};
        }
        let entries = Gauge::default();
        registry.register(
            "cw_traffic_resolver_content_entries",
            "Retained response-content fingerprints; expired entries clear on observation",
            entries.clone(),
        );
        let evictions = Counter::default();
        registry.register(
            "cw_traffic_resolver_content_evictions",
            "Response-content fingerprints evicted at the capacity limit",
            evictions.clone(),
        );
        let expirations = Counter::default();
        registry.register(
            "cw_traffic_resolver_content_expirations",
            "Response-content fingerprints expired at the retention limit",
            expirations.clone(),
        );
        Self {
            messages: family!("cw_traffic_resolver_messages", "Resolver wire kinds; received messages have passed gossip-ID deduplication, not consensus validation"),
            bytes: family!("cw_traffic_resolver_payload_bytes", "Resolver payload bytes by decoded wire kind, not TCP wire bytes"),
            content: family!("cw_traffic_resolver_content_observations", "Same response bytes within stage/topic, excluding request ID; author/ID comparisons use the previous observation"),
            content_bytes: family!("cw_traffic_resolver_content_bytes", "Response content bytes classified by bounded fingerprinting; repeats do not imply uselessness"),
            skipped: family!("cw_traffic_resolver_content_skipped", "Responses excluded from content fingerprinting"),
            skipped_bytes: family!("cw_traffic_resolver_content_skipped_bytes", "Response content bytes excluded from fingerprinting"),
            entries, evictions, expirations, seen: HashMap::new(), order: VecDeque::new(), limit: MAX_RESPONSES,
        }
    }

    pub(crate) fn observe(
        &mut self,
        stage: &'static str,
        message: &TrafficMessage<'_>,
        body: &[u8],
        now: Instant,
        budget: &mut usize,
    ) {
        while self
            .order
            .front()
            .is_some_and(|(_, inserted)| now.duration_since(*inserted) >= RETENTION)
        {
            let (key, _) = self.order.pop_front().unwrap();
            self.seen.remove(&key);
            self.expirations.inc();
        }
        self.entries.set(self.seen.len() as i64);
        let parsed = parse(body);
        let labels = KindLabels {
            stage,
            kind: parsed.as_ref().map_or("invalid_encoding", |p| p.kind),
        };
        self.messages.get_or_create(&labels).inc();
        self.bytes
            .get_or_create(&labels)
            .inc_by(message.data.len() as u64);
        let Some(Wire {
            kind: "response",
            id,
            content,
        }) = parsed
        else {
            return;
        };
        let reason = if content.len() > MAX_BODY_BYTES {
            Some("oversize")
        } else if message.source.is_none() {
            Some("missing_author")
        } else {
            None
        };
        if let Some(reason) = reason {
            self.skip(stage, reason, content.len());
            return;
        }
        let author_bytes = message.source.unwrap().to_bytes();
        let cost = content
            .len()
            .saturating_add(author_bytes.len())
            .saturating_add(128);
        if cost > *budget {
            self.skip(stage, "hash_budget", content.len());
            return;
        }
        *budget -= cost;
        let author: [u8; 32] = Sha256::digest(&author_bytes).into();
        let mut hash = Sha256::new();
        hash.update(b"cw-resolver-content-v1");
        hash.update((stage.len() as u64).to_be_bytes());
        hash.update(stage.as_bytes());
        hash.update(message.topic);
        hash.update(content);
        let key: [u8; 32] = hash.finalize().into();
        let observation = if let Some(previous) = self.seen.get_mut(&key) {
            let outcome = if author != previous.author {
                "repeat_other_author"
            } else if id != previous.id {
                "repeat_same_author_changed_id"
            } else {
                "repeat_same_author_same_id"
            };
            *previous = Seen { author, id };
            outcome
        } else {
            if self.seen.len() >= self.limit {
                let (key, _) = self.order.pop_front().unwrap();
                self.seen.remove(&key);
                self.evictions.inc();
            }
            self.seen.insert(key, Seen { author, id });
            self.order.push_back((key, now));
            "first_seen"
        };
        self.entries.set(self.seen.len() as i64);
        let labels = ContentLabels { stage, observation };
        self.content.get_or_create(&labels).inc();
        self.content_bytes
            .get_or_create(&labels)
            .inc_by(content.len() as u64);
    }

    fn skip(&self, stage: &'static str, reason: &'static str, bytes: usize) {
        let labels = SkipLabels { stage, reason };
        self.skipped.get_or_create(&labels).inc();
        self.skipped_bytes
            .get_or_create(&labels)
            .inc_by(bytes as u64);
    }
}

struct Wire<'a> {
    kind: &'static str,
    id: u64,
    content: &'a [u8],
}
/// Commonware resolver 2026.7 wire: u64 ID, u8 kind; View requests carry u64,
/// responses carry a u32 varint length and bytes. Bounded header reads, no allocation.
fn parse(body: &[u8]) -> Option<Wire<'_>> {
    let id = u64::from_be_bytes(body.get(..8)?.try_into().ok()?);
    let kind = *body.get(8)?;
    let rest = &body[9..];
    match kind {
        0 if rest.len() == 8 => Some(Wire {
            kind: "request",
            id,
            content: rest,
        }),
        2 if rest.is_empty() => Some(Wire {
            kind: "error",
            id,
            content: rest,
        }),
        1 => {
            let mut length = 0u32;
            for i in 0..5 {
                let byte = *rest.get(i)?;
                if i == 4 && byte > 0x0f {
                    return None;
                }
                length |= u32::from(byte & 0x7f) << (i * 7);
                if byte & 0x80 == 0 {
                    // Commonware rejects nonminimal unsigned varints.
                    if i > 0 && byte == 0 {
                        return None;
                    }
                    let content = &rest[i + 1..];
                    return (content.len() == length as usize).then_some(Wire {
                        kind: "response",
                        id,
                        content,
                    });
                }
            }
            None
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::PeerId;
    fn response(id: u64, content: &[u8]) -> Vec<u8> {
        use commonware_codec::Write;
        let mut out = Vec::new();
        id.write(&mut out);
        1u8.write(&mut out);
        bytes::Bytes::copy_from_slice(content).write(&mut out);
        out
    }
    #[test]
    fn parses_wire_kinds_lengths_and_rejects_malformed_headers() {
        for n in [0, 1, 127, 128, 150, 16384] {
            let encoded = response(9, &vec![7; n]);
            let parsed = parse(&encoded).unwrap();
            assert_eq!(parsed.kind, "response");
            assert_eq!(parsed.id, 9);
            assert_eq!(parsed.content.len(), n);
            assert!(parse(&encoded[..encoded.len() - 1]).is_none());
        }
        use commonware_codec::Write;
        let mut request = Vec::new();
        1u64.write(&mut request);
        0u8.write(&mut request);
        8u64.write(&mut request);
        assert_eq!(parse(&request).unwrap().kind, "request");
        request.push(0);
        assert!(parse(&request).is_none());
        let mut error = 1u64.to_be_bytes().to_vec();
        error.push(2);
        assert_eq!(parse(&error).unwrap().kind, "error");
        for bytes in [
            &b""[..],
            &b"short"[..],
            &b"12345678\x01\x80\x00"[..],
            &b"12345678\x01\xff\xff\xff\xff\x10"[..],
        ] {
            assert!(parse(bytes).is_none());
        }
    }
    #[test]
    fn fingerprints_cross_request_and_author_replies_without_crossing_topics_or_stages() {
        let mut registry = Registry::default();
        let mut diag = ResolverTrafficDiagnostics::new(&mut registry);
        let now = Instant::now();
        let author = PeerId::random();
        let other = PeerId::random();
        let topic = [1u8; 33];
        let mut budget = 1_000_000;
        for (id, peer) in [(1, &author), (2, &author), (3, &other), (3, &other)] {
            let body = response(id, b"certificate");
            let m = TrafficMessage {
                source: Some(peer),
                topic: &topic,
                data: &body,
            };
            diag.observe("receive_unique", &m, &body, now, &mut budget);
        }
        for outcome in [
            "first_seen",
            "repeat_same_author_changed_id",
            "repeat_other_author",
            "repeat_same_author_same_id",
        ] {
            assert_eq!(
                diag.content
                    .get_or_create(&ContentLabels {
                        stage: "receive_unique",
                        observation: outcome
                    })
                    .get(),
                1
            );
        }
        let body = response(4, b"certificate");
        let m = TrafficMessage {
            source: Some(&author),
            topic: &topic,
            data: &body,
        };
        diag.observe("publish_attempt", &m, &body, now, &mut budget);
        let topic2 = [2u8; 33];
        let m = TrafficMessage {
            topic: &topic2,
            ..m
        };
        diag.observe("receive_unique", &m, &body, now, &mut budget);
        assert_eq!(diag.seen.len(), 3);
        let mut exported = String::new();
        prometheus_client::encoding::text::encode(&mut exported, &registry).unwrap();
        assert!(!exported.contains(&author.to_string()));
        assert!(!exported.contains("request_id="));
        assert!(!exported.contains("certificate"));
    }
    #[test]
    fn bounds_cache_expiry_and_shared_hash_work() {
        let mut registry = Registry::default();
        let mut diag = ResolverTrafficDiagnostics::new(&mut registry);
        diag.limit = 1;
        let now = Instant::now();
        let author = PeerId::random();
        let topic = [1u8; 33];
        let mut budget = 1_000_000;
        for content in [b"one".as_slice(), b"two".as_slice()] {
            let body = response(1, content);
            let m = TrafficMessage {
                source: Some(&author),
                topic: &topic,
                data: &body,
            };
            diag.observe("receive_unique", &m, &body, now, &mut budget);
        }
        assert_eq!(diag.seen.len(), 1);
        assert_eq!(diag.evictions.get(), 1);
        let body = response(2, b"two");
        let m = TrafficMessage {
            source: Some(&author),
            topic: &topic,
            data: &body,
        };
        diag.observe("receive_unique", &m, &body, now + RETENTION, &mut budget);
        assert_eq!(diag.expirations.get(), 1);
        budget = 0;
        diag.observe("receive_unique", &m, &body, now + RETENTION, &mut budget);
        assert_eq!(
            diag.skipped
                .get_or_create(&SkipLabels {
                    stage: "receive_unique",
                    reason: "hash_budget"
                })
                .get(),
            1
        );
        let body = response(3, &vec![7; MAX_BODY_BYTES + 1]);
        let m = TrafficMessage { data: &body, ..m };
        diag.observe("receive_unique", &m, &body, now + RETENTION, &mut budget);
        assert_eq!(
            diag.skipped
                .get_or_create(&SkipLabels {
                    stage: "receive_unique",
                    reason: "oversize"
                })
                .get(),
            1
        );
    }
}
