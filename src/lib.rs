//! tokala — a dissenting quorum for agent actions.
//!
//! Named for the Tokala, the Kit Fox warrior society of the Lakota —
//! a sodality that deliberated and enforced together. This crate is a
//! council: independent *seats* each apply their own transform over a
//! normalized risk vector and vote in `[-1, 1]` with a one-line
//! rationale. Weighted consensus produces a verdict plus a **dissent
//! score** — the record shows not just what was decided but what each
//! mind voted and why.
//!
//! Deliberation is pure computation: microseconds, deterministic, safe
//! on any thread. Under a human the verdict is counsel; under autopilot
//! the council holds the gate — unanimous approve executes, anything
//! contested escalates.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

// ───────────────────────────── features ─────────────────────────────

/// A proposed action reduced to a fixed numeric vector the seats vote
/// on. Every field is normalized to `0.0..=1.0`.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct Features {
    /// Does the action destroy, overwrite, send, or remove state?
    pub destructiveness: f64,
    /// 1.0 = cannot be undone, 0.0 = fully reversible.
    pub irreversibility: f64,
    /// Reach: 0 = single temp file, 1 = system-wide or external network.
    pub blast_radius: f64,
    /// Touches credentials, keys, personal data, or protected paths.
    pub target_sensitivity: f64,
    /// Requires elevated privilege (sudo, launchd, admin APIs).
    pub privilege: f64,
    /// Breadth of objects affected (wildcards, recursion, directories).
    pub scope_mass: f64,
    /// Resource or time cost.
    pub cost: f64,
    /// How unusual versus routine use (0 = routine).
    pub novelty: f64,
}

impl Features {
    /// Aggregate risk — the shared baseline every seat weighs differently.
    pub fn risk(&self) -> f64 {
        0.30 * self.destructiveness
            + 0.22 * self.irreversibility
            + 0.16 * self.blast_radius
            + 0.12 * self.target_sensitivity
            + 0.10 * self.privilege
            + 0.05 * self.scope_mass
            + 0.05 * self.cost
    }
}

// ───────────────────────────── encoding ─────────────────────────────

fn term_score(terms: &[&str], haystack: &str) -> f64 {
    let hits = terms.iter().filter(|t| haystack.contains(*t)).count();
    (hits as f64 * 0.34).min(1.0)
}

const DESTRUCTIVE: &[&str] = &[
    "rm ", "rm -", "delete", "remove", "unlink", "rmdir", "dd ", "mkfs", "format",
    "truncate", "> /dev", "shred", "drop ", "overwrite", "kill ", "pkill",
    "killall", "shutdown", "reboot", "halt", "poweroff", "kill -9", "kill -s",
    "pmset sleep", "umount", "wipedisk",
];
const PRIVILEGE: &[&str] = &[
    "sudo", "do shell script", "launchctl", "dscl", "chmod 777", "chown",
    "csrutil", "nvram", "systemsetup", "diskutil",
];
const SENSITIVE: &[&str] = &[
    ".ssh", ".aws", ".gnupg", "keychain", "id_rsa", "id_ed25519", "password",
    "secret", "token", "credential", ".env", "/etc/", "/var/", "/system/",
    "/usr/", "/bin/", "library/keychains",
];
const NETWORK: &[&str] = &[
    "curl", "wget", "http://", "https://", "ssh ", "scp ", "ftp", "nc ", "ncat",
    "socket", "send", "mail", "smtp",
];
const MASS: &[&str] = &["-r", "-rf", "-f", "*", "...", "--recursive", "all"];

/// Heuristic encoder: tool name + arguments → [`Features`].
///
/// Ported from Bad Apple's `ActionEncoder`. Piped remote execution
/// (`curl x.sh | sh`) is unverifiable code from the network — scored
/// near-worst-case by construction.
pub fn encode(tool: &str, args: &BTreeMap<String, String>) -> Features {
    let text = args.values().cloned().collect::<Vec<_>>().join(" ").to_lowercase();
    let path = args
        .get("path")
        .or_else(|| args.get("file"))
        .or_else(|| args.get("dir"))
        .cloned()
        .unwrap_or_default()
        .to_lowercase();
    let cmd = args
        .get("command")
        .or_else(|| args.get("script"))
        .cloned()
        .unwrap_or_default()
        .to_lowercase();

    let piped_shell = cmd.contains("| sh")
        || cmd.contains("|sh")
        || cmd.contains("| bash")
        || cmd.contains("|bash")
        || cmd.contains("| zsh")
        || (cmd.contains("sh -c") && cmd.contains("curl"))
        || (cmd.contains("bash -c") && cmd.contains("curl"));

    let mut f = Features::default();
    match tool {
        "run_shell" => {
            f.destructiveness = term_score(DESTRUCTIVE, &format!(" {cmd}"));
            if cmd.contains("rm") && (cmd.contains("-r") || cmd.contains("-f")) {
                f.destructiveness = f.destructiveness.max(0.85);
            }
            if piped_shell {
                f.destructiveness = f.destructiveness.max(0.75);
                f.blast_radius = f.blast_radius.max(0.8);
            }
            f.irreversibility = if f.destructiveness > 0.3 { 0.9 } else { 0.35 };
            if cmd.contains("git checkout") || cmd.contains("git restore") {
                f.irreversibility = 0.75;
            }
            f.blast_radius = if cmd.contains("sudo") || cmd.starts_with("launchctl") {
                0.7
            } else {
                f.blast_radius.max(0.35)
            };
            f.privilege = term_score(PRIVILEGE, &cmd);
            f.scope_mass = term_score(MASS, &cmd);
            f.target_sensitivity = term_score(SENSITIVE, &format!("{cmd} {text}"));
            f.cost = if cmd.contains("curl") || cmd.contains("wget") { 0.4 } else { 0.15 };
            f.novelty = 0.4;
            if NETWORK.iter().any(|t| cmd.contains(t)) {
                f.blast_radius = f.blast_radius.max(0.55);
            }
        }
        "write_file" => {
            f.target_sensitivity = term_score(SENSITIVE, &format!("{path} {text}"));
            f.destructiveness = if std::path::Path::new(args.get("path").map(|s| s.as_str()).unwrap_or("")).exists() {
                0.55
            } else {
                0.2
            };
            // Writing credentials/config is dangerous even when new —
            // a bad authorized_keys locks you out of your own machine.
            if f.target_sensitivity > 0.3 {
                f.destructiveness = f.destructiveness.max(0.65);
            }
            f.irreversibility = if f.destructiveness > 0.4 { 0.75 } else { 0.15 };
            f.blast_radius = 0.25;
            f.scope_mass = 0.1;
            f.privilege = 0.05;
            f.cost = 0.1;
            f.novelty = 0.3;
        }
        "run_applescript" => {
            f.destructiveness = term_score(DESTRUCTIVE, &cmd) * 0.7;
            f.irreversibility = 0.5;
            f.blast_radius = 0.6; // drives other apps
            f.privilege = term_score(PRIVILEGE, &cmd);
            f.target_sensitivity = term_score(SENSITIVE, &cmd);
            f.scope_mass = 0.3;
            f.cost = 0.15;
            f.novelty = 0.45;
        }
        "run_shortcut" => {
            f.destructiveness = 0.3;
            f.irreversibility = 0.4;
            f.blast_radius = 0.55;
            f.privilege = 0.2;
            f.scope_mass = 0.25;
            f.cost = 0.2;
            f.novelty = 0.45;
        }
        "index_documents" => {
            f.destructiveness = 0.05;
            f.irreversibility = 0.05;
            f.blast_radius = 0.2;
            f.target_sensitivity = term_score(SENSITIVE, &path);
            f.scope_mass = if path.is_empty() || path == "~" { 0.7 } else { 0.4 };
            f.cost = 0.35;
            f.novelty = 0.25;
        }
        "screen_capture" => {
            f.destructiveness = 0.0;
            f.irreversibility = 0.0;
            f.blast_radius = 0.25;
            f.target_sensitivity = 0.7; // the screen may show private content
            f.privilege = 0.1;
            f.scope_mass = 0.15;
            f.cost = 0.1;
            f.novelty = 0.3;
        }
        "clear_working_memory" => {
            f.destructiveness = 0.55;
            f.irreversibility = 0.85;
            f.blast_radius = 0.2;
            f.target_sensitivity = 0.3;
            f.scope_mass = 0.5;
            f.cost = 0.05;
            f.novelty = 0.35;
        }
        "write_working_memory" | "consolidate_memory" => {
            f.destructiveness = 0.15;
            f.irreversibility = 0.3;
            f.blast_radius = 0.15;
            f.target_sensitivity = 0.25;
            f.scope_mass = 0.2;
            f.cost = 0.1;
            f.novelty = 0.3;
        }
        _ => {
            // Unlisted tools get a cautious middle reading.
            f.destructiveness = term_score(DESTRUCTIVE, &format!(" {text}"));
            f.irreversibility = if f.destructiveness > 0.3 { 0.7 } else { 0.4 };
            f.blast_radius = 0.4;
            f.target_sensitivity = term_score(SENSITIVE, &text);
            f.privilege = term_score(PRIVILEGE, &text);
            f.scope_mass = term_score(MASS, &text);
            f.cost = 0.25;
            f.novelty = 0.5;
        }
    }
    f
}

// ───────────────────────────── seats ────────────────────────────────

/// One seat's ballot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vote {
    pub seat: String,
    pub display: String,
    /// -1 deny … +1 approve.
    pub vote: f64,
    pub rationale: String,
}

type VoteFn = fn(&Features) -> f64;
type RationaleFn = fn(&Features, f64) -> &'static str;

/// One mind on the council — deterministic: the same features always
/// produce the same vote from the same seat.
pub struct Seat {
    pub id: &'static str,
    pub display: &'static str,
    /// Consensus weight — how strongly the seat's vote counts.
    pub weight: f64,
    pub vote_fn: VoteFn,
    pub rationale_fn: RationaleFn,
}

fn tanh(x: f64) -> f64 {
    x.tanh()
}

/// The fourteen-seat roster — four financial minds (Buffett, Dalio,
/// Musk, Jobs) and ten strategists — ported seat-for-seat from Bad
/// Apple's council, weights and personality transforms intact.
pub fn strategists() -> Vec<Seat> {
    vec![
        Seat {
            id: "buffett", display: "Buffett", weight: 1.4,
            vote_fn: |f| tanh(1.5 * (0.55 - f.risk() - 0.3 * f.irreversibility)),
            rationale_fn: |f, _| {
                if f.irreversibility > 0.5 { "no margin of safety on an irreversible move" }
                else if f.risk() < 0.3 { "downside protected — within the circle" }
                else { "risk outside the circle of competence" }
            },
        },
        Seat {
            id: "dalio", display: "Dalio", weight: 1.2,
            vote_fn: |f| tanh(1.2 * (0.5 - f.risk()) - 0.2 * (f.scope_mass - 0.5)),
            rationale_fn: |f, _| {
                if f.scope_mass > 0.5 { "concentrated bet — no diversification here" }
                else { "balanced enough to hold" }
            },
        },
        Seat {
            id: "musk", display: "Musk", weight: 1.0,
            vote_fn: |f| tanh(0.9 - f.risk() + 0.2 * f.novelty),
            rationale_fn: |f, _| {
                if f.novelty > 0.4 { "new ground — momentum favors it" }
                else { "move fast, iterate after" }
            },
        },
        Seat {
            id: "jobs", display: "Jobs", weight: 0.9,
            vote_fn: |f| tanh(1.3 * (0.5 - f.risk() - 0.4 * f.scope_mass)),
            rationale_fn: |f, _| {
                if f.scope_mass > 0.4 { "sprawl — this lacks focus" }
                else { "simple and decisive — yes" }
            },
        },
        Seat {
            id: "sun_tzu", display: "Sun Tzu", weight: 1.5,
            vote_fn: |f| tanh(1.6 * (0.55 - 0.5 * f.risk() - 0.5 * f.irreversibility)),
            rationale_fn: |f, _| {
                if f.irreversibility > 0.5 { "win first, then fight — this commits before the ground is proven" }
                else { "the ground is favorable and the retreat line stays open" }
            },
        },
        Seat {
            id: "clausewitz", display: "Clausewitz", weight: 1.3,
            vote_fn: |f| tanh(1.4 * (0.45 - f.risk() - 0.25 * f.scope_mass - 0.15 * f.privilege)),
            rationale_fn: |f, _| {
                if f.scope_mass + f.privilege > 0.7 { "too much friction — moving parts will seize" }
                else { "friction is manageable; the plan survives contact" }
            },
        },
        Seat {
            id: "musashi", display: "Musashi", weight: 1.1,
            vote_fn: |f| tanh(1.4 * (0.5 - f.blast_radius) + 0.2 * (1.0 - f.scope_mass)),
            rationale_fn: |f, _| {
                if f.blast_radius > 0.5 { "too broad — strike with one clean cut, not ten" }
                else { "one cut, one purpose — do it" }
            },
        },
        Seat {
            id: "machiavelli", display: "Machiavelli", weight: 1.0,
            vote_fn: |f| tanh(1.0 * (0.55 - f.risk()) + 0.3 * (1.0 - f.privilege)),
            rationale_fn: |f, _| {
                if f.privilege > 0.4 { "spending authority you may need later" }
                else { "preserves options and keeps control" }
            },
        },
        Seat {
            id: "napoleon", display: "Napoleon", weight: 1.0,
            vote_fn: |f| tanh(0.7 - 0.6 * f.risk()),
            rationale_fn: |f, _| {
                if f.risk() < 0.45 { "speed and mass — strike now" }
                else { "even audacity needs reserves" }
            },
        },
        Seat {
            id: "hannibal", display: "Hannibal", weight: 0.9,
            vote_fn: |f| tanh(0.5 - 0.4 * f.risk() + 0.3 * f.novelty),
            rationale_fn: |f, _| {
                if f.novelty > 0.4 { "the unexpected route is the advantage" }
                else { "we find a way or we make one — carefully here" }
            },
        },
        Seat {
            id: "aurelius", display: "Aurelius", weight: 1.5,
            vote_fn: |f| tanh(1.8 * (0.4 - f.risk())),
            rationale_fn: |f, _| {
                if f.risk() > 0.4 { "restraint — the obstacle is the risk itself" }
                else { "small, reversible, just — proceed" }
            },
        },
        Seat {
            id: "boyd", display: "Boyd", weight: 1.1,
            vote_fn: |f| tanh(1.3 * (0.5 - 0.4 * f.risk()) + 0.5 * (1.0 - f.irreversibility) - 0.25),
            rationale_fn: |f, _| {
                if f.irreversibility > 0.5 { "wrong tempo — an irreversible move ends your loop" }
                else { "fast and reversible keeps the OODA loop ours" }
            },
        },
        Seat {
            id: "genghis", display: "Genghis", weight: 0.9,
            vote_fn: |f| tanh(0.6 - 0.5 * f.risk() + 0.25 * f.scope_mass),
            rationale_fn: |f, _| {
                if f.scope_mass > 0.4 { "bold scale is the play — commit fully" }
                else { "efficient strike, minimal exposure" }
            },
        },
        Seat {
            id: "patton", display: "Patton", weight: 0.8,
            vote_fn: |f| 0.7 - 0.5 * f.risk(),
            rationale_fn: |f, _| {
                if f.risk() > 0.6 { "audacity, yes — suicide, no" }
                else { "a good plan violently executed beats hesitation" }
            },
        },
    ]
}

// ───────────────────────────── verdict ──────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Approve,
    Deny,
    Abstain,
}

/// The council's ruling: the decision, the mean, the dissent, and
/// every seat's ballot with its rationale — the dissent is part of the
/// record, not a footnote.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub decision: Decision,
    /// Weighted mean vote, -1…1.
    pub mean: f64,
    /// Weighted stddev across seats — disagreement level.
    pub dissent: f64,
    pub votes: Vec<Vote>,
}

impl Verdict {
    /// True when the council cannot give a clean go: abstain, deny, or
    /// dissent above the ceiling. Under autopilot these escalate.
    pub fn contested(&self, dissent_ceiling: f64) -> bool {
        self.decision != Decision::Approve || self.dissent > dissent_ceiling
    }

    /// Unanimous approval — every seat votes clearly for the action.
    /// Autopilot auto-executes only on unanimity.
    pub fn unanimous_approve(&self, approve_threshold: f64) -> bool {
        self.decision == Decision::Approve
            && self.votes.iter().all(|v| v.vote >= approve_threshold)
    }

    /// Compact line for prompts and notifications.
    pub fn summary(&self) -> String {
        let for_count = self.votes.iter().filter(|v| v.vote > 0.15).count();
        let against = self.votes.iter().filter(|v| v.vote < -0.15).count();
        let abstain = self.votes.len() - for_count - against;
        let strongest = self
            .votes
            .iter()
            .max_by(|a, b| a.vote.abs().partial_cmp(&b.vote.abs()).unwrap());
        let mut s = format!(
            "Council {for_count}–{against}{}{:?} (dissent {:.2})",
            if abstain > 0 { format!("–{abstain}abst ") } else { " ".into() },
            self.decision,
            self.dissent
        );
        if let Some(v) = strongest {
            s.push_str(&format!(" · loudest: {} — \"{}\"", v.display, v.rationale));
        }
        s
    }
}

// ───────────────────────────── council ──────────────────────────────

/// Deliberation thresholds, ported from Bad Apple's council.
pub const DISSENT_CEILING: f64 = 0.55;
pub const APPROVE_THRESHOLD: f64 = 0.15;
pub const DENY_THRESHOLD: f64 = -0.15;

/// The quorum. Deliberate with [`deliberate`](Self::deliberate); every
/// verdict can be journaled as NDJSON for the audit record.
pub struct Council {
    pub seats: Vec<Seat>,
    pub dissent_ceiling: f64,
    pub approve_threshold: f64,
    pub deny_threshold: f64,
    pub journal_path: Option<PathBuf>,
}

impl Default for Council {
    fn default() -> Self {
        Self {
            seats: strategists(),
            dissent_ceiling: DISSENT_CEILING,
            approve_threshold: APPROVE_THRESHOLD,
            deny_threshold: DENY_THRESHOLD,
            journal_path: None,
        }
    }
}

impl Council {
    /// The default fourteen-seat strategist council.
    pub fn new() -> Self {
        Self::default()
    }

    /// A council of custom seats.
    pub fn with_seats(seats: Vec<Seat>) -> Self {
        Self {
            seats,
            ..Self::default()
        }
    }

    /// Journal every deliberation to `path` as NDJSON.
    pub fn with_journal(mut self, path: PathBuf) -> Self {
        self.journal_path = Some(path);
        self
    }

    /// Deliberate a proposed tool call: encode → vote → verdict.
    /// Pure computation — microseconds, deterministic.
    pub fn deliberate(&self, tool: &str, args: &BTreeMap<String, String>) -> Verdict {
        let f = encode(tool, args);
        self.deliberate_features(&f)
    }

    /// Deliberate an already-encoded feature vector.
    pub fn deliberate_features(&self, f: &Features) -> Verdict {
        let mut votes = Vec::with_capacity(self.seats.len());
        let mut wsum = 0.0;
        let mut mean = 0.0;
        for seat in &self.seats {
            let v = (seat.vote_fn)(f).clamp(-1.0, 1.0);
            votes.push(Vote {
                seat: seat.id.to_string(),
                display: seat.display.to_string(),
                vote: v,
                rationale: (seat.rationale_fn)(f, v).to_string(),
            });
            mean += v * seat.weight;
            wsum += seat.weight;
        }
        mean = if wsum > 0.0 { mean / wsum } else { 0.0 };

        let mut var_sum = 0.0;
        for (i, seat) in self.seats.iter().enumerate() {
            let d = votes[i].vote - mean;
            var_sum += d * d * seat.weight;
        }
        let dissent = if wsum > 0.0 { (var_sum / wsum).sqrt() } else { 0.0 };

        let decision = if mean >= self.approve_threshold {
            Decision::Approve
        } else if mean <= self.deny_threshold {
            Decision::Deny
        } else {
            Decision::Abstain
        };

        let verdict = Verdict {
            decision,
            mean,
            dissent,
            votes,
        };
        self.journal(&verdict);
        verdict
    }

    /// Gate helper: `true` when autopilot may execute without asking —
    /// unanimous approval with dissent under the ceiling.
    pub fn may_execute(&self, verdict: &Verdict) -> bool {
        verdict.unanimous_approve(self.approve_threshold)
            && verdict.dissent <= self.dissent_ceiling
    }

    fn journal(&self, verdict: &Verdict) {
        let Some(path) = &self.journal_path else { return };
        if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(path) {
            if let Ok(line) = serde_json::to_string(verdict) {
                let _ = f.write_all(line.as_bytes());
                let _ = f.write_all(b"\n");
            }
        }
    }
}
