//! How long each persistent-sector capacity message has waited for a GLOBAL
//! proposal of this node: the frame of the first proposal that left it out,
//! kept by message key across its copies at several ranks and its sender's
//! resends, so a certificate resent after its rank aged out keeps its place.

use std::collections::HashMap;

/// Messages whose wait is kept: about four ranks' worth of capacity
/// messages ([`super::CAPACITY_MESSAGES_PER_RANK`]). Past it, the waits of
/// the messages seen longest ago go first.
const WAITS_KEPT: usize = 16_384;

/// A message's wait.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Wait {
    /// The frame of the first proposal of this node that left it out.
    since: u64,
    /// The frame of the latest proposal of this node that saw it.
    seen: u64,
}

/// The waits of the capacity messages proposals of this node left out.
#[derive(Default)]
pub(super) struct CapacityWaits {
    waits: HashMap<[u8; 32], Wait>,
}

impl CapacityWaits {
    /// The frame from which `key` has waited, if a proposal of an earlier
    /// frame than `frame` left it out.
    pub(super) fn since(&self, key: &[u8; 32], frame: u64) -> Option<u64> {
        self.waits
            .get(key)
            .map(|wait| wait.since)
            .filter(|since| *since < frame)
    }

    /// Record a proposal of `frame`: it saw `present` and left out `left`.
    /// A wait ends once `gone` (carried by a finalized frame, or consumed by
    /// an executed ancestor), or when no proposal has seen it for
    /// `kept_frames`: its sender stopped sending it.
    pub(super) fn note(
        &mut self,
        frame: u64,
        present: &[[u8; 32]],
        left: &[[u8; 32]],
        gone: impl Fn(&[u8; 32]) -> bool,
        kept_frames: u64,
    ) {
        for key in present {
            if let Some(wait) = self.waits.get_mut(key) {
                wait.seen = wait.seen.max(frame);
            }
        }
        for key in left {
            let wait = self.waits.entry(*key).or_insert(Wait {
                since: frame,
                seen: frame,
            });
            wait.since = wait.since.min(frame);
            wait.seen = wait.seen.max(frame);
        }
        self.waits
            .retain(|key, wait| !gone(key) && frame.saturating_sub(wait.seen) <= kept_frames);
        if self.waits.len() > WAITS_KEPT {
            let mut seen: Vec<u64> = self.waits.values().map(|wait| wait.seen).collect();
            let cut = seen.len() - WAITS_KEPT;
            let (_, oldest, _) = seen.select_nth_unstable(cut);
            let oldest = *oldest;
            self.waits.retain(|_, wait| wait.seen >= oldest);
        }
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.waits.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A wait starts at the first proposal that leaves a message out, lasts
    /// across proposals that leave it again or do not see it within the
    /// kept frames, and ends once it is gone or unseen past them.
    #[test]
    fn a_wait_starts_at_the_first_proposal_that_leaves_it_and_ends_when_gone() {
        let (a, b) = ([1u8; 32], [2u8; 32]);
        let mut waits = CapacityWaits::default();
        waits.note(10, &[a, b], &[a], |_| false, 5);
        assert_eq!(waits.since(&a, 10), None, "not before a later frame");
        assert_eq!(waits.since(&a, 11), Some(10));
        assert_eq!(waits.since(&b, 11), None, "b was taken");
        waits.note(12, &[a], &[a], |_| false, 5);
        assert_eq!(waits.since(&a, 13), Some(10), "the first leave counts");
        waits.note(17, &[], &[], |_| false, 5);
        assert_eq!(
            waits.since(&a, 18),
            Some(10),
            "unseen within the kept frames"
        );
        waits.note(18, &[], &[], |_| false, 5);
        assert_eq!(waits.since(&a, 19), None, "unseen past them");
        waits.note(20, &[b], &[b], |_| false, 5);
        waits.note(21, &[b], &[], |key| *key == b, 5);
        assert_eq!(waits.since(&b, 22), None, "carried");
        assert_eq!(waits.len(), 0);
    }
}
