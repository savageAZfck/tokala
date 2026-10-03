# tokala

A dissenting quorum for agent actions. Named for the Tokala — the Kit Fox warrior society of the Lakota, a sodality that deliberated and enforced together.

Extracted seat-for-seat from Bad Apple's fourteen-mind council.

## What it does

A proposed action is encoded into a normalized **risk vector** — destructiveness, irreversibility, blast radius, target sensitivity, privilege, scope mass, cost, novelty. Each seat applies its own personality transform and votes in `[-1, 1]` with a one-line rationale. Weighted consensus produces the verdict; a weighted stddev produces the **dissent score**.

The record shows not just what was decided but **what each mind voted and why**. Dissent isn't a footnote — it's in the verdict.

## The gate contract

- `verdict.decision` — approve / deny / abstain from the weighted mean
- `verdict.contested()` — not approve, or dissent above the ceiling (0.55)
- `verdict.unanimous_approve()` — every seat clearly for it
- `council.may_execute()` — unanimous approve *and* dissent under ceiling — the autopilot bar; anything less escalates to a human

## The roster

Fourteen deterministic seats ported intact — the four financial minds (**Buffett, Dalio, Musk, Jobs**) and ten strategists (**Sun Tzu, Clausewitz, Musashi, Machiavelli, Napoleon, Hannibal, Aurelius, Boyd, Genghis, Patton**), each with its own weights, vote transform, and in-voice rationale. Buffett votes the margin of safety; Boyd votes whether the move preserves your OODA loop; Aurelius restrains everything.

## Usage

```rust
use tokala::Council;
use std::collections::BTreeMap;

let council = Council::new();
let mut args = BTreeMap::new();
args.insert("command".into(), "sudo rm -rf /var/lib/app".into());

let verdict = council.deliberate("run_shell", &args);
if council.may_execute(&verdict) {
    run();
} else {
    println!("{}", verdict.summary()); // contested — escalate to the human
    // Council 6–5 Abstain (dissent 0.31) · loudest: Sun Tzu — "win first, then fight…"
}
```

Deliberation is microseconds, pure computation, deterministic — the same features always yield the same verdict. Journal every verdict to NDJSON with `.with_journal(path)`.

## Origin

In Bad Apple the council holds the tool gate under autopilot: unanimous-approve executes, contested votes escalate to the human with the dissent preserved. Majority-vote libraries exist; a parliament that keeps its minority report on an immutable record didn't. Now it does.

## License

MIT
