# tokala specification

A dissenting quorum for agent actions.

## Pipeline

`deliberate(tool, args)` = `deliberate_features(encode(tool, args))`.

1. **Encode** — heuristic `tool + args → Features` (8 fields, all
   normalized to `0.0..=1.0`). Unlisted tools get a cautious middle
   reading; piped remote shell (`curl x.sh | sh`) is scored
   near-worst-case by construction.
2. **Vote** — each seat computes `vote_fn(features)` clamped to
   `[-1, 1]` and a rationale string. Seats are pure functions:
   deterministic, no state.
3. **Tally** — weighted mean `mean`; weighted stddev `dissent`.
4. **Decide** — `mean ≥ approve_threshold → approve`,
   `mean ≤ deny_threshold → deny`, else `abstain`.

## Constants (defaults, from Bad Apple's council)

- `dissent_ceiling = 0.55`
- `approve_threshold = 0.15`
- `deny_threshold = -0.15`

## Risk aggregate

`risk = 0.30·destructiveness + 0.22·irreversibility + 0.16·blast_radius
+ 0.12·target_sensitivity + 0.10·privilege + 0.05·scope_mass + 0.05·cost`

## Verdict contract

- `contested()` — `decision ≠ approve || dissent > ceiling`
- `unanimous_approve()` — `decision = approve` and every vote
  `≥ approve_threshold`
- `may_execute(verdict)` — unanimous approve **and** dissent under
  ceiling. The autopilot bar.

## Invariants

- Every verdict carries every seat's vote **and** rationale — the
  minority report is structurally part of the record.
- Deliberation is pure and deterministic: same features, same verdict.
- `dissent` is a weighted stddev, not a boolean — marginal and heated
  consensus are distinguishable.

## Non-goals

- tokala deliberates; it does not execute. Wiring `may_execute` to a
  tool gate is the integrator's.
- Seats are deterministic heuristics, not oracles — they bound risk
  posture, not intent correctness.
