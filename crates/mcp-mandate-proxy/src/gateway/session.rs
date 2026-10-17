//! MCP sessions on the gateway. Each has its own gate (and so its own taint
//! and audit session), belongs to the caller who opened it, and maps the
//! gateway's session id to the server's.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mcp_mandate_gate::Gate;

use super::identity::Caller;

/// Most sessions open at once, in all and per caller.
const MAX_SESSIONS: usize = 10_000;
const MAX_SESSIONS_PER_CALLER: usize = 100;

pub struct Session {
    /// The id the client sees: random, and never the server's own.
    pub id: String,
    pub server: String,
    pub caller: Caller,
    gate: Mutex<Gate>,
    upstream_id: Mutex<Option<String>>,
    last_used: Mutex<Instant>,
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
        }
    }

    /// Runs `check` with the session's gate. `None` if a check panicked
    /// earlier: the session is then unusable.
    pub fn with_gate<T>(&self, check: impl FnOnce(&mut Gate) -> T) -> Option<T> {
        self.gate.lock().ok().map(|mut gate| check(&mut gate))
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
