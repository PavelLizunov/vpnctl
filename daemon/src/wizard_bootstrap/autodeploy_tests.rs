use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Barrier;

async fn outcome(mut completion: Completion) -> Outcome {
    loop {
        if let Some(value) = *completion.borrow_and_update() {
            return value;
        }
        completion.changed().await.unwrap();
    }
}

#[tokio::test]
async fn mutations_during_apply_coalesce_and_servers_are_independent() {
    let coordinator = Arc::new(Coordinator::default());
    let (first, worker) = coordinator.request("a".into());
    assert_eq!(
        coordinator.status("a").unwrap().phase,
        AutodeployPhase::Queued
    );
    let entered = Arc::new(Barrier::new(2));
    let released = Arc::new(Barrier::new(2));
    let calls = Arc::new(AtomicUsize::new(0));
    let task = tokio::spawn(worker.unwrap().run(
        {
            let entered = Arc::clone(&entered);
            let released = Arc::clone(&released);
            let calls = Arc::clone(&calls);
            move || {
                let entered = Arc::clone(&entered);
                let released = Arc::clone(&released);
                let pass = calls.fetch_add(1, Ordering::SeqCst);
                async move {
                    if pass == 0 {
                        entered.wait().await;
                        released.wait().await;
                    }
                    Ok(())
                }
            }
        },
        || std::future::ready(()),
    ));
    entered.wait().await;
    assert_eq!(
        coordinator.status("a").unwrap().phase,
        AutodeployPhase::Running
    );
    let (second, duplicate) = coordinator.request("a".into());
    assert!(duplicate.is_none());
    let (third, duplicate) = coordinator.request("a".into());
    assert!(duplicate.is_none());
    // A different node finishes while a is held at a deterministic barrier.
    let (other, other_worker) = coordinator.request("b".into());
    other_worker
        .unwrap()
        .run(|| std::future::ready(Ok(())), || std::future::ready(()))
        .await;
    assert_eq!(outcome(other).await, Ok(()));
    released.wait().await;
    task.await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    for receiver in [first, second, third] {
        assert_eq!(outcome(receiver).await, Ok(()));
    }
    assert_eq!(coordinator.status("a"), None);
}

#[tokio::test]
async fn retirement_cannot_lose_request_or_erase_successor() {
    let coordinator = Arc::new(Coordinator::default());
    let (completion, worker) = coordinator.request("retire".into());
    let worker = worker.unwrap();
    worker.begin();
    let (during, duplicate) = coordinator.request("retire".into());
    assert!(duplicate.is_none());
    assert!(
        worker.finish(Ok(()), 1),
        "request before retirement schedules followup"
    );
    worker.begin();
    assert!(!worker.finish(Ok(()), 2));
    assert_eq!(outcome(completion).await, Ok(()));
    assert_eq!(outcome(during).await, Ok(()));
    let (next, successor) = coordinator.request("retire".into());
    assert!(
        successor.is_some(),
        "request after retirement owns successor"
    );
    drop(worker); // old cleanup cannot overwrite the successor's status
    assert_eq!(
        coordinator.status("retire").unwrap().phase,
        AutodeployPhase::Queued
    );
    successor
        .unwrap()
        .run(|| std::future::ready(Ok(())), || std::future::ready(()))
        .await;
    assert_eq!(outcome(next).await, Ok(()));
}

#[tokio::test]
async fn stale_and_competing_lock_are_bounded_and_final_errors_observable() {
    for failure in [
        Failure::Stale,
        Failure::Contention,
        Failure::Deploy,
        Failure::MissingKey,
    ] {
        let coordinator = Arc::new(Coordinator::default());
        let (completion, worker) = coordinator.request("retry".into());
        let calls = AtomicUsize::new(0);
        worker
            .unwrap()
            .run(
                || {
                    calls.fetch_add(1, Ordering::SeqCst);
                    std::future::ready(Err(failure))
                },
                || std::future::ready(()),
            )
            .await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            if failure.retryable() { MAX_PASSES } else { 1 }
        );
        assert_eq!(outcome(completion).await, Err(failure));
        assert_eq!(
            coordinator.status("retry").unwrap(),
            AutodeployStatus {
                phase: AutodeployPhase::Failed,
                message: failure.message()
            }
        );
        let (_, retry) = coordinator.request("retry".into());
        assert!(
            retry.is_some(),
            "explicit retry starts a fresh bounded operation"
        );
    }
}

#[tokio::test]
async fn stale_followup_converges_and_continuous_mutation_cannot_spin() {
    let coordinator = Arc::new(Coordinator::default());
    let (completion, worker) = coordinator.request("stale".into());
    let calls = AtomicUsize::new(0);
    worker
        .unwrap()
        .run(
            || {
                std::future::ready(if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    Err(Failure::Stale)
                } else {
                    Ok(())
                })
            },
            || std::future::ready(()),
        )
        .await;
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(outcome(completion).await, Ok(()));

    let (completion, worker) = coordinator.request("busy".into());
    let calls = AtomicUsize::new(0);
    worker
        .unwrap()
        .run(
            || {
                calls.fetch_add(1, Ordering::SeqCst);
                let (_, duplicate) = coordinator.request("busy".into());
                assert!(duplicate.is_none());
                std::future::ready(Ok(()))
            },
            || std::future::ready(()),
        )
        .await;
    assert_eq!(calls.load(Ordering::SeqCst), MAX_PASSES);
    assert_eq!(outcome(completion).await, Err(Failure::Exhausted));
    assert_eq!(
        coordinator.status("busy").unwrap().phase,
        AutodeployPhase::Failed
    );
}

#[tokio::test]
async fn interrupted_worker_is_failure_and_cleanup_is_bounded() {
    let coordinator = Arc::new(Coordinator::default());
    let (completion, worker) = coordinator.request("interrupted".into());
    drop(worker);
    assert_eq!(outcome(completion).await, Err(Failure::Interrupted));
    let (_, active) = coordinator.request("active".into());
    for i in 0..MAX_FAILURES + 3 {
        let (_, worker) = coordinator.request(format!("failure-{i}"));
        drop(worker);
    }
    assert_eq!(coordinator.entries().len(), MAX_FAILURES + 1);
    assert_eq!(
        coordinator.status("active").unwrap().phase,
        AutodeployPhase::Queued
    );
    Coordinator::cleanup(&mut coordinator.entries(), Instant::now() + FAILURE_TTL);
    assert_eq!(
        coordinator.entries().len(),
        1,
        "TTL must not evict active worker"
    );
    drop(active);
    assert!(
        Coordinator::default().status("active").is_none(),
        "restart has no success observation"
    );
}

#[tokio::test]
async fn separate_inventories_with_same_server_id_never_share_worker_or_status() {
    let first_dir = tempfile::tempdir().unwrap();
    let second_dir = tempfile::tempdir().unwrap();
    let first = SqliteInventory::open(&first_dir.path().join("inv.db"))
        .await
        .unwrap();
    let second = SqliteInventory::open(&second_dir.path().join("inv.db"))
        .await
        .unwrap();
    let reopened = SqliteInventory::open(&first_dir.path().join("inv.db"))
        .await
        .unwrap();
    assert_eq!(
        coordination_key(&first, "same"),
        coordination_key(&first.clone(), "same")
    );
    assert_eq!(
        coordination_key(&first, "same"),
        coordination_key(&reopened, "same")
    );
    assert_ne!(
        coordination_key(&first, "same"),
        coordination_key(&second, "same")
    );
    let (_, worker) = coordinator().request(coordination_key(&first, "same"));
    assert!(autodeploy_status(&first, "same").is_some());
    assert!(autodeploy_status(&second, "same").is_none());
    let (_, second_worker) = coordinator().request(coordination_key(&second, "same"));
    assert!(
        second_worker.is_some(),
        "same id in another inventory requires its own worker"
    );
    worker
        .unwrap()
        .run(
            || std::future::ready(Err(Failure::Deploy)),
            || std::future::ready(()),
        )
        .await;
    assert_eq!(
        autodeploy_status(&first, "same").unwrap().phase,
        AutodeployPhase::Failed
    );
    assert_eq!(
        autodeploy_status(&second, "same").unwrap().phase,
        AutodeployPhase::Queued
    );
    second_worker
        .unwrap()
        .run(|| std::future::ready(Ok(())), || std::future::ready(()))
        .await;
    assert_eq!(autodeploy_status(&second, "same"), None);
    assert_eq!(
        autodeploy_status(&first, "same").unwrap().phase,
        AutodeployPhase::Failed
    );
}

#[tokio::test]
async fn request_during_followup_delay_uses_next_pass_without_extra_worker() {
    let coordinator = Arc::new(Coordinator::default());
    let (completion, worker) = coordinator.request("delay".into());
    let calls = AtomicUsize::new(0);
    worker
        .unwrap()
        .run(
            || {
                std::future::ready(if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    Err(Failure::Contention)
                } else {
                    Ok(())
                })
            },
            || {
                let (_, duplicate) = coordinator.request("delay".into());
                assert!(duplicate.is_none());
                assert_eq!(
                    coordinator.status("delay").unwrap().phase,
                    AutodeployPhase::Queued
                );
                std::future::ready(())
            },
        )
        .await;
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(outcome(completion).await, Ok(()));
}
