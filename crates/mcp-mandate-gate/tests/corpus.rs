//! Runs the attack corpus (`corpus/*.json` at the repository root) through
//! the gate. Every attack must be stopped, every benign case must pass
//! untouched, and every known gap must still behave as documented, so a fix
//! gets noticed. See `corpus/README.md` for the format.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use mcp_mandate_audit::{AuditError, Event, Recorder};
use mcp_mandate_gate::{Action, Gate, SharedTaint};
use mcp_mandate_pin::{Inventory, Pins};
use mcp_mandate_policy::Policy;
use serde::Deserialize;
use serde_json::{Value, json};

const ALLOW_ALL: &str = "[[tools]]\nmatch = \"*\"\naction = \"allow\"\n";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CorpusFile {
    class: String,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    kind: CaseKind,
    about: String,
    policy: Option<String>,
    #[serde(default)]
    pinned: Pinned,
    #[serde(default)]
    skip_listing: bool,
    /// Values the gate treats as secrets, as the HTTPS gateway does with
    /// its upstream credentials.
    #[serde(default)]
    credentials: Vec<String>,
    steps: Vec<Step>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum CaseKind {
    Attack,
    Benign,
    KnownGap,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pinned {
    instructions: Option<String>,
    #[serde(default)]
    tools: Vec<Value>,
    #[serde(default)]
    prompts: Vec<Value>,
    #[serde(default)]
    resources: Vec<Value>,
    #[serde(default)]
    resource_templates: Vec<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Step {
    /// Which of the agent's servers (one gate each) the step goes through.
    #[serde(default = "first_gate")]
    gate: String,
    from: Side,
    send: Option<Value>,
    raw: Option<String>,
    expect: Outcome,
    seen: Option<Vec<String>>,
    #[serde(default)]
    absent: Vec<String>,
    #[serde(default)]
    present: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Side {
    Client,
    Server,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Outcome {
    Forward,
    Modify,
    Block,
    Drop,
}

fn first_gate() -> String {
    "a".to_owned()
}

/// An audit log that keeps nothing.
struct Discard;

impl Recorder for Discard {
    fn record(&mut self, _: &Event) -> Result<(), AuditError> {
        Ok(())
    }
}

/// The taint one agent's gates share.
#[derive(Default)]
struct AgentTaint(Mutex<Option<String>>);

impl SharedTaint for AgentTaint {
    fn get(&self) -> Option<String> {
        self.0.lock().unwrap().clone()
    }

    fn set(&self, source: &str) -> bool {
        *self.0.lock().unwrap() = Some(source.to_owned());
        true
    }
}

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus")
}

fn load() -> Vec<CorpusFile> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(corpus_dir())
        .expect("the corpus folder exists")
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    paths.sort();
    paths
        .iter()
        .map(|path| {
            let text = std::fs::read_to_string(path).unwrap();
            serde_json::from_str(&text)
                .unwrap_or_else(|error| panic!("{}: {error}", path.display()))
        })
        .collect()
}

fn line(message: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(message).unwrap();
    bytes.push(b'\n');
    bytes
}

/// What the gate did with a message, judged by where its output went.
fn outcome(from: Side, sent: &[u8], actions: &[Action]) -> Outcome {
    match (from, actions) {
        (_, []) => Outcome::Drop,
        (Side::Client, [Action::ToServer(out)]) | (Side::Server, [Action::ToClient(out)]) => {
            if out == sent {
                Outcome::Forward
            } else {
                Outcome::Modify
            }
        }
        _ => Outcome::Block,
    }
}

/// The names a list result shows.
fn names(message: &Value) -> Option<Vec<String>> {
    ["tools", "prompts", "resources", "resourceTemplates"]
        .iter()
        .find_map(|field| message["result"][field].as_array())
        .map(|items| {
            items
                .iter()
                .map(|item| {
                    ["name", "uri", "uriTemplate"]
                        .iter()
                        .find_map(|key| item[key].as_str())
                        .unwrap_or("(no name)")
                        .to_owned()
                })
                .collect()
        })
}

/// A gate for one of the case's servers, with everything pinned listed
/// unless the case skips that.
fn start_gate(case: &Case, agent: &Arc<AgentTaint>) -> Gate {
    let policy = Policy::parse(case.policy.as_deref().unwrap_or(ALLOW_ALL), Path::new("."))
        .unwrap_or_else(|error| panic!("{}: bad policy: {error}", case.id));
    let inventory = Inventory {
        instructions: case.pinned.instructions.clone(),
        tools: case.pinned.tools.clone(),
        prompts: case.pinned.prompts.clone(),
        resources: case.pinned.resources.clone(),
        resource_templates: case.pinned.resource_templates.clone(),
    };
    let pins = Pins::from_inventory("corpus", &inventory);
    let mut gate = Gate::new(policy, Some(pins), Box::new(Discard))
        .with_shared_taint(Arc::clone(agent) as Arc<dyn SharedTaint>);
    gate.add_secret_literals(case.credentials.iter().cloned());

    if !case.skip_listing {
        let lists = [
            ("tools/list", "tools", &case.pinned.tools),
            ("prompts/list", "prompts", &case.pinned.prompts),
            ("resources/list", "resources", &case.pinned.resources),
            (
                "resources/templates/list",
                "resourceTemplates",
                &case.pinned.resource_templates,
            ),
        ];
        for (method, field, items) in lists {
            if items.is_empty() {
                continue;
            }
            let id = format!("listing-{field}");
            gate.from_client(&line(
                &json!({"jsonrpc": "2.0", "id": id, "method": method}),
            ));
            gate.from_server(&line(
                &json!({"jsonrpc": "2.0", "id": id, "result": {field: items}}),
            ));
        }
    }
    gate
}

/// Runs one case; returns what went wrong, if anything.
fn run(case: &Case) -> Vec<String> {
    let agent = Arc::new(AgentTaint::default());
    let mut gates: BTreeMap<&str, Gate> = BTreeMap::new();
    let mut problems = Vec::new();
    for (number, step) in case.steps.iter().enumerate() {
        let sent = match (&step.send, &step.raw) {
            (Some(message), None) => line(message),
            (None, Some(raw)) => format!("{raw}\n").into_bytes(),
            _ => panic!(
                "{} step {}: give exactly one of `send` and `raw`",
                case.id,
                number + 1
            ),
        };
        let gate = gates
            .entry(step.gate.as_str())
            .or_insert_with(|| start_gate(case, &agent));
        let actions = match step.from {
            Side::Client => gate.from_client(&sent),
            Side::Server => gate.from_server(&sent),
        };
        let mut fail = |problem: String| problems.push(format!("step {}: {problem}", number + 1));
        let got = outcome(step.from, &sent, &actions);
        if got != step.expect {
            fail(format!("expected {:?}, got {got:?}", step.expect));
        }
        let output: String = actions
            .iter()
            .map(|action| match action {
                Action::ToClient(bytes) | Action::ToServer(bytes) => {
                    String::from_utf8_lossy(bytes).into_owned()
                }
            })
            .collect();
        for text in &step.absent {
            if output.contains(text.as_str()) {
                fail(format!("{text:?} got through"));
            }
        }
        for text in &step.present {
            if !output.contains(text.as_str()) {
                fail(format!("{text:?} is missing from {output:?}"));
            }
        }
        if let Some(expected) = &step.seen {
            let shown = serde_json::from_str::<Value>(&output)
                .ok()
                .and_then(|message| names(&message));
            if shown.as_ref() != Some(expected) {
                fail(format!(
                    "expected the client to see {expected:?}, it saw {shown:?}"
                ));
            }
        }
    }
    problems
}

#[test]
fn every_attack_is_stopped_and_every_benign_case_passes() {
    let files = load();
    let mut failures = Vec::new();
    let mut tally: BTreeMap<(String, CaseKind), (usize, usize)> = BTreeMap::new();
    let mut ids = std::collections::HashSet::new();
    for file in &files {
        for case in &file.cases {
            assert!(ids.insert(case.id.clone()), "duplicate case id {}", case.id);
            assert!(
                !case.about.is_empty(),
                "{}: say what the case is about",
                case.id
            );
            let problems = run(case);
            let entry = tally.entry((file.class.clone(), case.kind)).or_default();
            entry.1 += 1;
            if problems.is_empty() {
                entry.0 += 1;
            } else {
                failures.push(format!(
                    "{}/{} ({:?}): {}",
                    file.class,
                    case.id,
                    case.kind,
                    problems.join("; ")
                ));
            }
        }
    }

    println!("{:<16} {:<10} {:>6}", "class", "kind", "passed");
    for ((class, kind), (passed, total)) in &tally {
        println!(
            "{class:<16} {:<10} {passed:>3}/{total:<3}",
            format!("{kind:?}")
        );
    }
    let count = |kind: CaseKind| {
        tally
            .iter()
            .filter(|((_, k), _)| *k == kind)
            .map(|(_, (_, total))| total)
            .sum::<usize>()
    };
    assert!(
        failures.is_empty(),
        "{} case(s) failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
    assert!(
        count(CaseKind::Attack) >= 40,
        "the corpus has too few attacks"
    );
    assert!(
        count(CaseKind::Benign) >= 15,
        "the corpus has too few benign cases"
    );
}
