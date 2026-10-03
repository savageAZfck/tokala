# Threat model

tokala sits between an action-proposing component (an agent, a model,
a planner) and the executor. It assumes the proposer is competent but
not trusted — the council is the prior deliberation layer.

## What it defends against

- **Unilateral high-risk execution.** Nothing executes under autopilot
  without unanimous approval and low dissent; a single alarmed seat
  shows up in the record even when outvoted.
- **Stealthy destructive phrasing.** The encoder reads shell semantics
  (`rm -rf`, piped remote shell, `git checkout`) rather than trusting
  the tool's self-description.
- **Accountability gaps.** Every seat's ballot + rationale is on the
  verdict and journal — post-hoc review sees the dissent, not a
  smoothed-over "approved".

## What it does not defend against

- **Encoder evasion.** A hostile proposer can craft args that score
  benign while doing harm (obfuscated commands, novel tools the
  heuristic doesn't know). The encoder is a heuristic, not a parser —
  pair with policy and a posterior watchdog.
- **Seat capture.** Seats are deterministic functions baked at build
  time; an attacker who controls the build controls the council.
- **Unanimity as safety.** `may_execute` requires unanimity *of these
  fourteen minds* — a shared blind spot is a shared blind spot.
  Diversity of the roster is the mitigation.

## Design posture

Deterministic and legible over clever and opaque: a gate you can replay
and argue with beats a score you can't explain.
