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
