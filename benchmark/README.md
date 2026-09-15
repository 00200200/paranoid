# Benchmark

The point of this folder: an honest, reproducible answer to "does the skill
actually reduce vulnerabilities?" — not a marketing number.

## The question

> For the same security-sensitive coding tasks, does an agent with `paranoid`
> loaded produce fewer exploitable solutions than the same agent without it,
> holding functional correctness roughly equal?

We care about two numbers per condition:

- **exploit rate** — share of solutions that pass their functional test but fail
  a security test (an exploit succeeds). Lower is better.
- **correctness rate** — share that pass the functional test at all. The skill
  must not tank this to win on security.

## Method

1. **Tasks.** A set of backend tasks, each with (a) a functional test and (b) one
   or more exploit tests targeting a specific vuln class (IDOR, missing auth,
   injection, SSRF, …). We start from a small hand-written set in `tasks/` and
   can extend toward public benchmarks like [BaxBench](https://baxbench.com/)
   (392 tasks, 14 frameworks) for a larger, third-party-defined run.
2. **Conditions.** Same model, same prompts, temperature fixed. `baseline` = no
   skill; `paranoid` = skill loaded. N samples per task per condition.
3. **Score.** For each solution, run the functional test, then the exploit
   test(s). Record correctness and exploit outcomes.
4. **Report.** Exploit rate and correctness per condition, with the delta and a
   simple confidence interval. Publish the raw per-sample results, the exact
   prompts, model id, and date so anyone can re-run and check.

## Reproduce

```bash
# from repo root — harness lands here next
cd benchmark
cat tasks/README.md   # task format
# ./run.sh --model <id> --n 5   (coming with the first task set)
```

## Honesty rules for this benchmark

- No result in the README until the harness has produced it here.
- Publish the losses too — tasks where the skill didn't help or hurt correctness.
- Report the model and date; a number without them is meaningless as models move.
- When a public benchmark (BaxBench) is used, follow its methodology and say so,
  rather than inventing a favorable one.

_Status: harness + first task set in progress._
