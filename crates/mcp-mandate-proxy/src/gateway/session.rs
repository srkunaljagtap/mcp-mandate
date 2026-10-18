//! MCP sessions on the gateway. Each has its own gate (and so its own taint
//! and audit session), belongs to the caller who opened it, and maps the
//! gateway's session id to the server's.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mcp_mandate_gate::{Gate, SharedTaint};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};

use super::identity::Caller;

/// Most sessions open at once, in all and per caller.
const MAX_SESSIONS: usize = 10_000;
const MAX_SESSIONS_PER_CALLER: usize = 32;
/// Most requests in flight at once per session. A request answered with a
/// stream counts until the stream ends.
const MAX_REQUESTS_PER_SESSION: usize = 16;
/// Most server streams (GET) open at once per session.
const MAX_STREAMS_PER_SESSION: usize = 4;
/// Most answers to the server's own requests being sent at once per
/// session.
const MAX_ANSWERS_PER_SESSION: usize = 8;

pub struct Session {
    /// The id the client sees: random, and never the server's own.
    pub id: String,
    pub server: String,
    pub caller: Caller,
    /// An async lock, so a check waiting its turn doesn't hold a thread.
    gate: Arc<tokio::sync::Mutex<Gate>>,
    upstream_id: Mutex<Option<String>>,
    last_used: Mutex<Instant>,
    /// Set once the session is closed: nothing passes through it after.
    closed: watch::Sender<bool>,
    /// A check panicked, so the gate may be half-updated.
    broken: AtomicBool,
    requests: Arc<Semaphore>,
    streams: Arc<Semaphore>,
    answers: Arc<Semaphore>,
}

impl Session {
    pub fn new(server: &str, caller: Caller, gate: Gate) -> Self {
        Self {
            id: new_id(),
            server: server.to_owned(),
            caller,
            gate: Arc::new(tokio::sync::Mutex::new(gate)),
            upstream_id: Mutex::new(None),
            last_used: Mutex::new(Instant::now()),
            closed: watch::Sender::new(false),
            broken: AtomicBool::new(false),
            requests: Arc::new(Semaphore::new(MAX_REQUESTS_PER_SESSION)),
            streams: Arc::new(Semaphore::new(MAX_STREAMS_PER_SESSION)),
            answers: Arc::new(Semaphore::new(MAX_ANSWERS_PER_SESSION)),
        }
    }

    /// Runs `check` with the session's gate, on a thread where blocking is
    /// fine: a check takes CPU time, and writes the audit log, which may
    /// wait for a lock. `None` once the session is closed, or if a check
    /// panicked: the session is then unusable.
    pub async fn check<T: Send + 'static>(
        &self,
        check: impl FnOnce(&mut Gate) -> T + Send + 'static,
    ) -> Option<T> {
        if self.unusable() {
            return None;
        }
        let mut gate = Arc::clone(&self.gate).lock_owned().await;
        // Closed while waiting its turn: its end is recorded, so nothing
        // more is.
        if self.unusable() {
            return None;
        }
        match tokio::task::spawn_blocking(move || check(&mut gate)).await {
            Ok(result) => Some(result),
            Err(_) => {
                self.broken.store(true, Ordering::SeqCst);
                None
            }
        }
    }

    fn unusable(&self) -> bool {
        *self.closed.borrow() || self.broken.load(Ordering::SeqCst)
    }

    /// Closes the session: nothing passes through it from now on, and its
    /// streams stop. Returns whether this call closed it; whoever did then
    /// [records its end](Self::record_end).
    pub fn close(&self) -> bool {
        !self.closed.send_replace(true)
    }

    /// Completes once the session is closed.
    pub async fn closed(&self) {
        let mut closed = self.closed.subscribe();
        let _ = closed.wait_for(|closed| *closed).await;
    }

    /// Records the end of the session in its audit log, once any check
    /// under way is done.
    pub async fn record_end(&self) {
        let mut gate = Arc::clone(&self.gate).lock_owned().await;
        let _ = tokio::task::spawn_blocking(move || gate.end_session(None)).await;
    }

    /// Counts a request in flight; `None` when the session has too many.
    /// It's uncounted when the returned permit drops.
    pub fn start_request(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.requests).try_acquire_owned().ok()
    }

    /// Counts a new server stream; `None` when the session has too many.
    pub fn open_stream(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.streams).try_acquire_owned().ok()
    }

    /// Counts an answer being sent to the server; `None` when the session
    /// has too many.
    pub fn start_answer(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.answers).try_acquire_owned().ok()
    }

    pub fn upstream_id(&self) -> Option<String> {
        self.upstream_id.lock().ok().and_then(|id| id.clone())
    }

    pub fn set_upstream_id(&self, id: Option<String>) {
        if let Ok(mut current) = self.upstream_id.lock() {
            *current = id;
        }
    }

    pub fn touch(&self) {
        if let Ok(mut last_used) = self.last_used.lock() {
            *last_used = Instant::now();
        }
    }

    fn idle_for(&self) -> Duration {
        self.last_used
            .lock()
            .map_or(Duration::MAX, |last_used| last_used.elapsed())
    }
}

#[derive(Default)]
pub struct Sessions {
    map: Mutex<HashMap<String, Arc<Session>>>,
}

#[derive(Debug, thiserror::Error)]
#[error("too many open sessions")]
pub struct Full;

impl Sessions {
    pub fn insert(&self, session: Arc<Session>) -> Result<(), Full> {
        let mut map = self.map.lock().map_err(|_| Full)?;
        let theirs = map
            .values()
            .filter(|open| open.caller.subject == session.caller.subject)
            .count();
        if map.len() >= MAX_SESSIONS || theirs >= MAX_SESSIONS_PER_CALLER {
            return Err(Full);
        }
        map.insert(session.id.clone(), session);
        Ok(())
    }

    /// The session `id` if `caller` opened it on `server`. Anyone else gets
    /// nothing, as if it didn't exist.
    pub fn get(&self, id: &str, server: &str, caller: &Caller) -> Option<Arc<Session>> {
        let map = self.map.lock().ok()?;
        map.get(id)
            .filter(|session| session.server == server && session.caller.subject == caller.subject)
            .cloned()
    }

    pub fn remove(&self, id: &str) -> Option<Arc<Session>> {
        self.map.lock().ok()?.remove(id)
    }

    /// Removes and returns sessions idle for longer than `idle`.
    pub fn sweep(&self, idle: Duration) -> Vec<Arc<Session>> {
        let Ok(mut map) = self.map.lock() else {
            return Vec::new();
        };
        let stale: Vec<String> = map
            .iter()
            .filter(|(_, session)| session.idle_for() > idle)
            .map(|(id, _)| id.clone())
            .collect();
        stale.iter().filter_map(|id| map.remove(id)).collect()
    }

    /// The callers with at least one open session.
    pub fn callers(&self) -> HashSet<String> {
        self.map
            .lock()
            .map(|map| {
                map.values()
                    .map(|session| session.caller.subject.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn drain(&self) -> Vec<Arc<Session>> {
        self.map
            .lock()
            .map(|mut map| map.drain().map(|(_, session)| session).collect())
            .unwrap_or_default()
    }
}

/// 256 random bits, hex.
fn new_id() -> String {
    let mut bytes = [0u8; 32];
    aws_lc_rs::rand::fill(&mut bytes).expect("the system's random source works");
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Taint per caller, shared by all their sessions on every server: reading
/// through one server holds sending through any other. A caller's taint is
/// forgotten once they have no session open.
#[derive(Default)]
pub struct CallerTaints {
    map: Mutex<HashMap<String, String>>,
}

impl CallerTaints {
    /// Forgets the taint of callers with no open session.
    pub fn keep_only(&self, callers: &HashSet<String>) {
        if let Ok(mut map) = self.map.lock() {
            map.retain(|caller, _| callers.contains(caller));
        }
    }

    pub fn for_caller(self: &Arc<Self>, caller: &str) -> CallerTaint {
        CallerTaint {
            taints: Arc::clone(self),
            caller: caller.to_owned(),
        }
    }
}

/// One caller's view of [`CallerTaints`], given to each of their gates.
pub struct CallerTaint {
    taints: Arc<CallerTaints>,
    caller: String,
}

impl SharedTaint for CallerTaint {
    fn get(&self) -> Option<String> {
        match self.taints.map.lock() {
            Ok(map) => map.get(&self.caller).cloned(),
            // Fail closed.
            Err(_) => Some("another session of this caller".to_owned()),
        }
    }

    fn set(&self, source: &str) {
        if let Ok(mut map) = self.taints.map.lock() {
            map.entry(self.caller.clone())
                .or_insert_with(|| source.to_owned());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use std::sync::atomic::AtomicUsize;

    use mcp_mandate_audit::{AuditError, Event, EventKind, Recorder};
    use mcp_mandate_policy::Policy;

    use super::*;

    /// An audit log that only counts session ends.
    struct Ends(Arc<AtomicUsize>);

    impl Recorder for Ends {
        fn record(&mut self, event: &Event) -> Result<(), AuditError> {
            if event.event == EventKind::SessionEnd {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
            Ok(())
        }
    }

    fn session(caller: &str) -> Arc<Session> {
        session_counting_ends(caller, &Arc::default())
    }

    fn session_counting_ends(caller: &str, ends: &Arc<AtomicUsize>) -> Arc<Session> {
        let policy = Policy::parse("", Path::new(".")).unwrap();
        let caller = Caller {
            subject: caller.to_owned(),
            client: None,
            expires: u64::MAX,
        };
        let gate = Gate::new(policy, None, Box::new(Ends(Arc::clone(ends))));
        Arc::new(Session::new("alpha", caller, gate))
    }

    #[test]
    fn each_caller_has_a_session_limit_of_their_own() {
        let sessions = Sessions::default();
        for _ in 0..MAX_SESSIONS_PER_CALLER {
            sessions.insert(session("alice")).unwrap();
        }
        assert!(sessions.insert(session("alice")).is_err());
        sessions.insert(session("bob")).unwrap();
    }

    type Start = fn(&Session) -> Option<OwnedSemaphorePermit>;

    #[test]
    fn a_session_has_limits_on_streams_requests_and_answers() {
        let session = session("alice");
        let limits: [(Start, usize); 3] = [
            (Session::open_stream, MAX_STREAMS_PER_SESSION),
            (Session::start_request, MAX_REQUESTS_PER_SESSION),
            (Session::start_answer, MAX_ANSWERS_PER_SESSION),
        ];
        for (start, limit) in limits {
            let open: Vec<OwnedSemaphorePermit> =
                (0..limit).map(|_| start(&session).unwrap()).collect();
            assert!(start(&session).is_none());
            drop(open);
            assert!(start(&session).is_some());
        }
    }

    #[tokio::test]
    async fn a_session_closes_once_and_nothing_passes_through_it_after() {
        let ends = Arc::default();
        let session = session_counting_ends("alice", &ends);
        assert_eq!(session.check(|gate| gate.taint()).await, Some(None));
        let waiting = tokio::spawn({
            let session = Arc::clone(&session);
            async move { session.closed().await }
        });
        assert!(session.close());
        assert!(!session.close(), "closed already");
        session.record_end().await;
        assert_eq!(ends.load(Ordering::SeqCst), 1);
        assert_eq!(session.check(|gate| gate.taint()).await, None);
        tokio::time::timeout(Duration::from_secs(5), waiting)
            .await
            .expect("its streams were told")
            .unwrap();
    }

    #[tokio::test]
    async fn a_check_that_panics_leaves_the_session_unusable() {
        let session = session("alice");
        assert_eq!(session.check(|_| panic!("a bug")).await, None::<()>);
        assert_eq!(session.check(|gate| gate.taint()).await, None);
    }

    #[test]
    fn idle_sessions_are_swept_and_a_callers_taint_ends_with_their_sessions() {
        let sessions = Sessions::default();
        sessions.insert(session("alice")).unwrap();
        let taints = Arc::new(CallerTaints::default());
        taints.for_caller("alice").set("fetch");
        assert!(sessions.sweep(Duration::from_secs(60)).is_empty());
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(sessions.sweep(Duration::from_millis(10)).len(), 1);
        taints.keep_only(&sessions.callers());
        assert_eq!(taints.for_caller("alice").get(), None);
    }
}
