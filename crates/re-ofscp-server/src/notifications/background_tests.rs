//! Tests of the background queue (`background.rs`).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use super::*;

/// Long enough for a task that could run to have run.
const SETTLE: Duration = Duration::from_millis(100);

fn job(channel: &str, message: &str) -> Job {
    Job {
        channel_id: channel.to_owned(),
        group_id: format!("g_{channel}"),
        message_id: message.to_owned(),
    }
}

/// A run that records each batch, in the order turns start.
fn recorder() -> (Run, Arc<Mutex<Vec<Batch>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    let run: Run = Arc::new(move |b: Batch| {
        log.lock().unwrap().push(b);
        Box::pin(async {})
    });
    (run, seen)
}

/// `(channel, ids)` of each recorded batch.
fn turns(seen: &Mutex<Vec<Batch>>) -> Vec<(String, Vec<String>)> {
    seen.lock()
        .unwrap()
        .iter()
        .map(|b| (b.channel_id.clone(), b.message_ids.clone()))
        .collect()
}

fn ids(names: &[&str]) -> Vec<String> {
    names.iter().map(|s| (*s).to_owned()).collect()
}

#[tokio::test]
async fn flush_waits_for_every_id_including_queued_ones() {
    let done = Arc::new(AtomicUsize::new(0));
    let (open, gate) = watch::channel(false);
    let counter = done.clone();
    let run: Run = Arc::new(move |b: Batch| {
        let counter = counter.clone();
        let mut gate = gate.clone();
        Box::pin(async move {
            let _ = gate.wait_for(|o| *o).await;
            counter.fetch_add(b.message_ids.len(), Ordering::SeqCst);
        })
    });
    let limits = Limits {
        slots: 2,
        batch: 2,
        ..Limits::default()
    };
    let bg = Background::with_limits(run, limits);
    for i in 0..12 {
        bg.enqueue(job(&format!("c{}", i % 3), &format!("m{i}")))
            .await;
    }
    assert_eq!(bg.unfinished(), 12);
    open.send_replace(true);
    bg.flush().await;
    assert_eq!(done.load(Ordering::SeqCst), 12);
    assert_eq!(bg.unfinished(), 0);
}

#[tokio::test]
async fn a_panicking_turn_counts_as_handled_and_the_rest_still_run() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    let run: Run = Arc::new(move |b: Batch| {
        let log = log.clone();
        Box::pin(async move {
            if b.message_ids == ["boom"] {
                panic!("boom");
            }
            log.lock().unwrap().push(b);
        })
    });
    let limits = Limits {
        slots: 1,
        batch: 1,
        ..Limits::default()
    };
    let bg = Background::with_limits(run, limits);
    let hold = bg.hold();
    bg.enqueue(job("a", "boom")).await;
    bg.enqueue(job("a", "after")).await;
    bg.enqueue(job("b", "other")).await;
    drop(hold);
    bg.flush().await;
    assert_eq!(bg.unfinished(), 0);
    assert_eq!(
        turns(&seen),
        vec![
            ("b".to_owned(), ids(&["other"])),
            ("a".to_owned(), ids(&["after"])),
        ]
    );
}

#[tokio::test]
async fn flush_with_nothing_queued_returns_at_once() {
    let (run, _) = recorder();
    Background::new(run).flush().await;
}

#[tokio::test]
async fn a_flooded_channel_takes_turns_with_the_others() {
    let (run, seen) = recorder();
    let limits = Limits {
        slots: 1,
        batch: 2,
        per_channel: 8,
        total: 64,
    };
    let bg = Background::with_limits(run, limits);
    let hold = bg.hold();
    for i in 1..=6 {
        bg.enqueue(job("flood", &format!("f{i}"))).await;
    }
    bg.enqueue(job("quiet", "q1")).await;
    // Coalesced: one entry per channel, two ready channels.
    {
        let s = bg.shared.lock();
        assert_eq!(s.channels.len(), 2);
        assert_eq!(s.ready.len(), 2);
        assert_eq!(s.queued, 7);
    }
    drop(hold);
    bg.flush().await;
    // The quiet channel waited one turn, not for the whole flood.
    assert_eq!(
        turns(&seen),
        vec![
            ("flood".to_owned(), ids(&["f1", "f2"])),
            ("quiet".to_owned(), ids(&["q1"])),
            ("flood".to_owned(), ids(&["f3", "f4"])),
            ("flood".to_owned(), ids(&["f5", "f6"])),
        ]
    );
    assert!(bg.shared.lock().channels.is_empty());
}

#[tokio::test]
async fn a_channel_is_in_one_turn_at_a_time_and_keeps_its_order() {
    let running = Arc::new(AtomicUsize::new(0));
    let most = Arc::new(AtomicUsize::new(0));
    let order = Arc::new(Mutex::new(Vec::new()));
    let (r, m, o) = (running.clone(), most.clone(), order.clone());
    let run: Run = Arc::new(move |b: Batch| {
        let (r, m, o) = (r.clone(), m.clone(), o.clone());
        Box::pin(async move {
            let now = r.fetch_add(1, Ordering::SeqCst) + 1;
            m.fetch_max(now, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(5)).await;
            o.lock().unwrap().extend(b.message_ids);
            r.fetch_sub(1, Ordering::SeqCst);
        })
    });
    let limits = Limits {
        slots: 4,
        batch: 1,
        ..Limits::default()
    };
    let bg = Background::with_limits(run, limits);
    let want: Vec<String> = (0..8).map(|i| format!("m{i}")).collect();
    for m in &want {
        bg.enqueue(job("one", m)).await;
    }
    bg.flush().await;
    assert_eq!(most.load(Ordering::SeqCst), 1);
    assert_eq!(*order.lock().unwrap(), want);
}

#[tokio::test]
async fn a_full_channel_makes_its_creates_wait_and_drops_nothing() {
    let (run, seen) = recorder();
    let limits = Limits {
        slots: 1,
        batch: 8,
        per_channel: 2,
        total: 64,
    };
    let bg = Arc::new(Background::with_limits(run, limits));
    let hold = bg.hold();
    bg.enqueue(job("a", "a1")).await;
    bg.enqueue(job("a", "a2")).await;
    // The channel is full: a third id waits...
    let waiting = {
        let bg = bg.clone();
        tokio::spawn(async move { bg.enqueue(job("a", "a3")).await })
    };
    tokio::time::sleep(SETTLE).await;
    assert!(!waiting.is_finished());
    assert_eq!(bg.unfinished(), 2);
    // ...while another channel's goes straight in.
    tokio::time::timeout(SETTLE, bg.enqueue(job("b", "b1")))
        .await
        .expect("another channel has room");
    drop(hold);
    waiting.await.unwrap();
    bg.flush().await;
    let mut got: Vec<String> = turns(&seen).into_iter().flat_map(|(_, i)| i).collect();
    got.sort();
    assert_eq!(got, ids(&["a1", "a2", "a3", "b1"]));
}

#[tokio::test]
async fn a_full_queue_makes_every_create_wait_until_a_turn_makes_room() {
    let (run, seen) = recorder();
    let limits = Limits {
        slots: 1,
        batch: 1,
        per_channel: 8,
        total: 3,
    };
    let bg = Arc::new(Background::with_limits(run, limits));
    let hold = bg.hold();
    for c in ["a", "b", "c"] {
        bg.enqueue(job(c, &format!("{c}1"))).await;
    }
    let waiting = {
        let bg = bg.clone();
        tokio::spawn(async move { bg.enqueue(job("d", "d1")).await })
    };
    tokio::time::sleep(SETTLE).await;
    assert!(!waiting.is_finished());
    assert_eq!(bg.shared.lock().queued, 3);
    drop(hold);
    waiting.await.unwrap();
    bg.flush().await;
    assert_eq!(turns(&seen).len(), 4);
}

#[tokio::test]
async fn a_hold_keeps_work_queued_until_dropped() {
    let (run, seen) = recorder();
    let bg = Background::new(run);
    let hold = bg.hold();
    bg.enqueue(job("a", "a1")).await;
    tokio::time::sleep(SETTLE).await;
    assert!(turns(&seen).is_empty());
    assert_eq!(bg.unfinished(), 1);
    drop(hold);
    bg.flush().await;
    assert_eq!(turns(&seen), vec![("a".to_owned(), ids(&["a1"]))]);
}
