//! MCP sessions on the gateway. Each has its own gate (and so its own taint
//! and audit session), belongs to the caller who opened it, and maps the
//! gateway's session id to the server's.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mcp_mandate_gate::{Gate, SharedTaint};

use super::identity::Caller;

/// Most sessions open at once, in all and per caller.
const MAX_SESSIONS: usize = 10_000;
const MAX_SESSIONS_PER_CALLER: usize = 32;
/// Most server streams (GET) open at once per session.
const MAX_STREAMS_PER_SESSION: usize = 4;

pub struct Session {
    /// The id the client sees: random, and never the server's own.
    pub id: String,
    pub server: String,
    pub caller: Caller,
    gate: Mutex<Gate>,
    upstream_id: Mutex<Option<String>>,
    last_used: Mutex<Instant>,
    /// Server streams (GET) open now.
    streams: Arc<AtomicUsize>,
}

impl Session {
    pub fn new(server: &str, caller: Caller, gate: Gate) -> Self {
        Self {
            id: new_id(),
            server: server.to_owned(),
            caller,
            gate: Mutex::new(gate),
            upstream_id: Mutex::new(None),
            last_used: Mutex::new(Instant::now()),
            streams: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Runs `check` with the session's gate. `None` if a check panicked
    /// earlier: the session is then unusable.
    pub fn with_gate<T>(&self, check: impl FnOnce(&mut Gate) -> T) -> Option<T> {
        self.gate.lock().ok().map(|mut gate| check(&mut gate))
    }

    /// Counts a new server stream; `None` when the session has too many.
    /// The stream is uncounted when the returned guard drops.
    pub fn open_stream(&self) -> Option<StreamGuard> {
        let open = self.streams.fetch_add(1, Ordering::SeqCst);
        let guard = StreamGuard(Arc::clone(&self.streams));
        (open < MAX_STREAMS_PER_SESSION).then_some(guard)
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

    /// Records the end of the session in its audit log.
    pub fn end(&self) {
        self.with_gate(|gate| gate.end_session(None));
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

/// Keeps a session's server stream counted while it's open.
pub struct StreamGuard(Arc<AtomicUsize>);

impl Drop for StreamGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
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

    use mcp_mandate_audit::{AuditError, Event, Recorder};
    use mcp_mandate_policy::Policy;

    use super::*;

    /// An audit log that keeps nothing.
    struct Discard;

    impl Recorder for Discard {
        fn record(&mut self, _: &Event) -> Result<(), AuditError> {
            Ok(())
        }
    }

    fn session(caller: &str) -> Arc<Session> {
        let policy = Policy::parse("", Path::new(".")).unwrap();
        let caller = Caller {
            subject: caller.to_owned(),
            client: None,
        };
        let gate = Gate::new(policy, None, Box::new(Discard));
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

    #[test]
    fn a_session_has_a_stream_limit() {
        let session = session("alice");
        let open: Vec<StreamGuard> = (0..MAX_STREAMS_PER_SESSION)
            .map(|_| session.open_stream().unwrap())
            .collect();
        assert!(session.open_stream().is_none());
        drop(open);
        assert!(session.open_stream().is_some());
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
