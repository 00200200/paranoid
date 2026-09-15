## What & why

<!-- What does this change and why? Link any issue. -->

## Type

- [ ] New benchmark task class (+ insecure/secure self-test refs)
- [ ] New `/hack-me` framework/language guide
- [ ] Independent-app proof under `examples/`
- [ ] Reference / skill content
- [ ] Fix / docs / other

## Checklist

- [ ] Benchmark self-test passes:
      `cd benchmark && python3 harness/run.py solutions/selftest_insecure solutions/selftest_secure`
      (insecure **100%**, secure **0%**)
- [ ] New task classes ship both an insecure and a secure reference solution.
- [ ] **Honesty:** any benchmark number was produced by the harness in this repo,
      with model + date; losses reported, not hidden.
- [ ] `/hack-me` content keeps the guardrails (own/authorized targets, localhost,
      non-destructive proofs).
- [ ] One logical change per commit, clear messages.
