//! Read-only observations of consensus history retention.

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use crate::adapters::{Digest, FrameFinalizer};

static NEXT_INSTANCE: AtomicU64 = AtomicU64::new(1);

pub(crate) fn next_instance() -> u64 {
    NEXT_INSTANCE.fetch_add(1, Ordering::Relaxed)
}

/// Observe certified outcomes without changing their delivery or acceptance.
pub(crate) struct ObservedFinalizer<F: FrameFinalizer> {
    inner: Arc<F>,
    pub(crate) finalized: AtomicU64,
    pub(crate) notarized: AtomicU64,
}

impl<F: FrameFinalizer> ObservedFinalizer<F> {
    pub(crate) fn new(inner: Arc<F>, floor: u64) -> Self {
        Self {
            inner,
            finalized: AtomicU64::new(floor),
            notarized: AtomicU64::new(floor),
        }
    }
}

impl<F: FrameFinalizer> FrameFinalizer for ObservedFinalizer<F> {
    fn on_notarized(&self, view: u64, digest: Digest, bytes: Option<Vec<u8>>) {
        self.notarized.fetch_max(view, Ordering::Relaxed);
        self.inner.on_notarized(view, digest, bytes);
    }

    fn on_finalized(
        &self,
        view: u64,
        digest: Digest,
        bytes: Option<Vec<u8>>,
        cert: Option<Vec<u8>>,
        locally_verified: bool,
    ) {
        self.finalized.fetch_max(view, Ordering::Relaxed);
        self.inner
            .on_finalized(view, digest, bytes, cert, locally_verified);
    }

    fn on_equivocation(&self, view: u64) {
        self.inner.on_equivocation(view);
    }
}

#[derive(Debug, Default, PartialEq)]
pub(crate) struct ViewSnapshot {
    pub(crate) current: Option<u64>,
    pub(crate) tracked: Option<u64>,
}

/// Select numeric gauges only; never log the encoded registry, whose families
/// can contain public keys. Missing/ambiguous gauges stay unknown, not zero.
pub(crate) fn view_snapshot(encoded: &str) -> ViewSnapshot {
    fn gauge(encoded: &str, suffix: &str) -> Option<u64> {
        let mut found = None;
        for line in encoded.lines().filter(|line| !line.starts_with('#')) {
            let mut fields = line.split_whitespace();
            let Some(name) = fields.next() else {
                continue;
            };
            let name = name.split('{').next()?;
            if !name.ends_with(suffix) {
                continue;
            }
            let value = fields.next()?.parse::<u64>().ok()?;
            if found.replace(value).is_some() {
                return None;
            }
        }
        found
    }
    ViewSnapshot {
        current: gauge(encoded, "_voter_state_current_view"),
        tracked: gauge(encoded, "_voter_state_tracked_views"),
    }
}

/// Resolver counters are aggregate outcomes, not a count of matched wire replies.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct ResolverSnapshot {
    pub(crate) fetch_success: Option<u64>,
    pub(crate) fetch_failure: Option<u64>,
    pub(crate) serve_success: Option<u64>,
    pub(crate) serve_failure: Option<u64>,
    pub(crate) fetch_active: Option<u64>,
    pub(crate) fetch_pending: Option<u64>,
    pub(crate) serve_processing: Option<u64>,
}

pub(crate) fn resolver_snapshot(encoded: &str) -> ResolverSnapshot {
    fn metric(encoded: &str, suffix: &str, status: Option<&str>) -> Option<u64> {
        let mut declaration = None;
        let mut found = None;
        for line in encoded.lines() {
            if let Some(rest) = line.strip_prefix("# TYPE ") {
                let name = rest.split_whitespace().next()?;
                let declared_suffix = suffix.strip_suffix("_total").unwrap_or(suffix);
                if name.ends_with(declared_suffix) {
                    if declaration.replace(name).is_some() {
                        return None;
                    }
                }
                continue;
            }
            if line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.rsplit_once(' ') else {
                continue;
            };
            let name = key.split('{').next()?;
            if !name.ends_with(suffix) {
                continue;
            }
            let expected = status.map(|value| format!("{{status=\"{value}\"}}"));
            if key.strip_prefix(name)? != expected.as_deref().unwrap_or("") {
                continue;
            }
            if found.replace(value.parse::<u64>().ok()?).is_some() {
                return None;
            }
        }
        // An explicitly registered empty counter family has zero observations;
        // an absent/ambiguous family is unknown. Never dump arbitrary labels.
        found.or_else(|| declaration.map(|_| 0))
    }
    ResolverSnapshot {
        fetch_success: metric(encoded, "_resolver_fetch_total", Some("Success")),
        fetch_failure: metric(encoded, "_resolver_fetch_total", Some("Failure")),
        serve_success: metric(encoded, "_resolver_serve_total", Some("Success")),
        serve_failure: metric(encoded, "_resolver_serve_total", Some("Failure")),
        fetch_active: metric(encoded, "_resolver_fetch_active", None),
        fetch_pending: metric(encoded, "_resolver_fetch_pending", None),
        serve_processing: metric(encoded, "_resolver_serve_processing", None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn selects_only_the_voter_gauges() {
        let metrics = "\n# HELP ignored text\n\nconsensus_engine_voter_state_current_view 16225\nconsensus_engine_voter_state_tracked_views 16224\nother_current_view 3\nconsensus_engine_voter_state_nullifications_total{leader=\"redacted\"} 900\n";
        assert_eq!(
            view_snapshot(metrics),
            ViewSnapshot {
                current: Some(16225),
                tracked: Some(16224)
            }
        );
    }

    #[test]
    fn missing_invalid_and_duplicate_values_are_unknown() {
        assert_eq!(view_snapshot(""), ViewSnapshot::default());
        for value in ["NaN", "-1", "1.5", "18446744073709551616"] {
            assert_eq!(
                view_snapshot(&format!("x_voter_state_current_view {value}\n")).current,
                None
            );
        }
        assert_eq!(
            view_snapshot("a_voter_state_current_view 3\nb_voter_state_current_view 4\n").current,
            None
        );
        assert_eq!(
            view_snapshot("x_voter_state_current_view 0\n").current,
            Some(0)
        );
    }

    #[test]
    fn reads_the_actual_runtime_registry() {
        use commonware_runtime::telemetry::metrics::{GaugeExt as _, MetricsExt as _};
        use commonware_runtime::{deterministic, Metrics, Runner as _, Supervisor as _};
        deterministic::Runner::default().start(|context| async move {
            let state = context
                .child("consensus")
                .child("engine")
                .child("voter")
                .child("state");
            let current = state.gauge("current_view", "current view");
            let tracked = state.gauge("tracked_views", "tracked views");
            current.try_set(16225).unwrap();
            tracked.try_set(16224).unwrap();
            assert_eq!(
                view_snapshot(&context.encode()),
                ViewSnapshot {
                    current: Some(16225),
                    tracked: Some(16224)
                }
            );
        });
    }

    #[test]
    fn resolver_outcomes_read_the_runtime_registry_without_sensitive_labels() {
        use commonware_runtime::telemetry::metrics::{status, GaugeExt as _, MetricsExt as _};
        use commonware_runtime::{deterministic, Metrics, Runner as _, Supervisor as _};
        deterministic::Runner::default().start(|context| async move {
            let resolver = context.child("consensus").child("engine").child("resolver");
            let fetch: status::Counter = resolver.family("fetch", "fetches");
            let serve: status::Counter = resolver.family("serve", "serves");
            let active = resolver.gauge("fetch_active", "active");
            active.try_set(4).unwrap();
            fetch.inc_by(status::Status::Success, 3);
            fetch.inc_by(status::Status::Failure, 2);
            serve.inc_by(status::Status::Success, 7);
            let result = resolver_snapshot(&context.encode());
            assert_eq!(result.fetch_success, Some(3));
            assert_eq!(result.fetch_failure, Some(2));
            assert_eq!(result.serve_success, Some(7));
            assert_eq!(result.serve_failure, Some(0));
            assert_eq!(result.fetch_active, Some(4));
            assert_eq!(result.fetch_pending, None);
        });
        assert_eq!(resolver_snapshot(""), ResolverSnapshot::default());
        assert_eq!(
            resolver_snapshot("x_resolver_fetch_total{status=\"Success\"} NaN").fetch_success,
            None
        );
        assert_eq!(resolver_snapshot("x_resolver_fetch_total{status=\"Success\"} 2\ny_resolver_fetch_total{status=\"Success\"} 3").fetch_success, None);
    }

    #[derive(Default)]
    struct Sink(Mutex<Vec<(u64, Option<Vec<u8>>, Option<Vec<u8>>, bool)>>);
    impl FrameFinalizer for Sink {
        fn on_notarized(&self, view: u64, _: Digest, bytes: Option<Vec<u8>>) {
            self.0.lock().unwrap().push((view, bytes, None, false));
        }
        fn on_finalized(
            &self,
            view: u64,
            _: Digest,
            bytes: Option<Vec<u8>>,
            cert: Option<Vec<u8>>,
            verified: bool,
        ) {
            self.0.lock().unwrap().push((view, bytes, cert, verified));
        }
        fn on_equivocation(&self, view: u64) {
            self.0.lock().unwrap().push((view, None, None, false));
        }
    }

    #[test]
    fn observations_preserve_callback_payloads_and_never_move_backwards() {
        let sink = Arc::new(Sink::default());
        let observed = ObservedFinalizer::new(sink.clone(), 10);
        let digest = crate::adapters::digest_from_identity([7; 32]);
        observed.on_notarized(12, digest, Some(vec![1]));
        observed.on_finalized(11, digest, Some(vec![2]), Some(vec![3]), true);
        observed.on_finalized(9, digest, None, None, false);
        observed.on_equivocation(8);
        assert_eq!(observed.finalized.load(Ordering::Relaxed), 11);
        assert_eq!(observed.notarized.load(Ordering::Relaxed), 12);
        assert_eq!(
            *sink.0.lock().unwrap(),
            vec![
                (12, Some(vec![1]), None, false),
                (11, Some(vec![2]), Some(vec![3]), true),
                (9, None, None, false),
                (8, None, None, false)
            ]
        );
    }
}
