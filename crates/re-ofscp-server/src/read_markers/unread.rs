//! Unread counts (spec §7.7, exact per lost-conn/ofscp#41): the messages
//! created in a channel after the reader's marker message, tombstones
//! included, that the reader did not write.
//!
//! Counted from message ordinals (`messages::ordinals`), never by reading
//! messages: the channel holds `messages` messages, the reader wrote `own`
//! of them, and the marker's message has ordinal `n` with `own_through`
//! of the reader's messages at or before it, so
//! `unread = (messages − n) − (own − own_through)`. With no marker, every
//! message the reader did not write is unread.

use crate::db::DbError;
use crate::messages::ordinals::Totals;

use super::store::StoredMarker;

/// The unread count in a channel whose [`Totals`] for the reader are
/// `totals`, given the reader's marker there. An error means the stored
/// counts contradict each other (a marker past the channel's messages, or
/// more of the reader's messages after it than messages at all).
pub fn count(scope: &str, totals: Totals, marker: Option<&StoredMarker>) -> Result<u64, DbError> {
    let (n, own_through) = marker.map_or((0, 0), |m| (m.n, m.own));
    let after = totals.messages.checked_sub(n);
    let own_after = totals.own.checked_sub(own_through);
    match (after, own_after) {
        (Some(after), Some(own_after)) if after >= 0 && own_after >= 0 && own_after <= after => {
            u64::try_from(after - own_after).map_err(|_| contradiction(scope))
        }
        _ => Err(contradiction(scope)),
    }
}

fn contradiction(scope: &str) -> DbError {
    DbError::Decode(format!("scope {scope}: its counts contradict its marker"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn marker(n: i64, own: i64) -> StoredMarker {
        StoredMarker {
            scope_id: "chn_1".to_owned(),
            message_id: "msg_1".to_owned(),
            n,
            own,
        }
    }

    #[test]
    fn counts_others_messages_after_the_marker_exactly() {
        let t = |messages, own| Totals { messages, own };
        // No marker: everything not the reader's.
        assert_eq!(count("s", t(0, 0), None).unwrap(), 0);
        assert_eq!(count("s", t(250, 50), None).unwrap(), 200);
        // Ten messages, the reader's are 2, 5 and 9; the marker is at 6
        // (two of theirs at or before it): after it are 7, 8, 9, 10, of
        // which 9 is theirs.
        assert_eq!(count("s", t(10, 3), Some(&marker(6, 2))).unwrap(), 3);
        // At the newest message: nothing unread.
        assert_eq!(count("s", t(10, 3), Some(&marker(10, 3))).unwrap(), 0);
        // Far past any former cap.
        assert_eq!(
            count("s", t(100_000, 0), Some(&marker(1, 0))).unwrap(),
            99_999
        );
    }

    #[test]
    fn contradictory_counts_are_errors_not_guesses() {
        let t = |messages, own| Totals { messages, own };
        assert!(count("s", t(5, 0), Some(&marker(6, 0))).is_err());
        assert!(count("s", t(5, 1), Some(&marker(3, 2))).is_err());
        assert!(count("s", t(5, 5), Some(&marker(1, 0))).is_err());
    }
}
