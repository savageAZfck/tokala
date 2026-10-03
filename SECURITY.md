# Security policy

## Reporting

Open a private security advisory on the GitHub repository, or email the
maintainer (see `Cargo.toml` authors). Do not file public issues for
gate-bypass findings — e.g. an argument encoding that yields unanimous
approval for a clearly destructive action.

## Scope

In scope:

- Encoding errors that wildly under-score destructive/irreversible
  actions (e.g. `rm -rf` variants that score 0 destructiveness).
- Verdict math bugs — wrong mean/dissent, or `may_execute` returning
  true on contested verdicts.
- Journal writes that drop or corrupt the vote record.

Out of scope:

- Semantic evasion (obfuscated commands the heuristic can't read) —
  inherent to any feature encoder; mitigated by layering, not by this
  crate alone.
- The execution side — tokala returns a verdict; whether the caller
  honors `contested()` is the integrator's contract.
- Custom-seat behavior — seats supplied via `Council::with_seats` are
  caller code.

## Guidance

- Journal every verdict (`with_journal`) on an append-only store so the
  dissent record can't be rewritten after the fact.
- Keep `may_execute` as the autopilot bar; route contested verdicts to
  a human, never to a retry loop.
- Compose with `akicita` (blast-radius bounds) upstream and a posterior
  watchdog downstream — the council is the prior, not the whole
  governance.
