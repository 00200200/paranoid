#!/usr/bin/env python3
"""paranoid benchmark scorer.

Usage:
    python3 harness/run.py [--only <ids>] [--json] <solutions_dir> [<solutions_dir> ...]

Each <solutions_dir> is one condition; its basename is the label (e.g.
solutions/baseline, solutions/paranoid). The dir contains one <task_id>.py per
task, each defining the function named in that task's spec.

Flags:
  --only a,b,c   score only these task ids.
  --json         print one machine-readable JSON summary to stdout (for CI /
                 diffing) instead of the human tables. Per-condition
                 results/<label>.json are still written either way.

For every task we run two checks against the solution:
  * functional -- does it do the job? (correctness)
  * secure     -- is the task's known exploit blocked? (security)

A solution is only "safe & correct" when both pass. We report, per condition,
the exploit rate *among functionally-correct solutions* -- i.e. of the code
that actually works, how much of it is exploitable. Results are written to
results/<label>.json.
"""
import importlib.util
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # benchmark/
sys.path.insert(0, ROOT)
TASKS_DIR = os.path.join(ROOT, "tasks")
RESULTS_DIR = os.path.join(ROOT, "results")


def _load(path, modname):
    spec = importlib.util.spec_from_file_location(modname, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def discover_tasks():
    tasks = []
    for name in sorted(os.listdir(TASKS_DIR)):
        check_path = os.path.join(TASKS_DIR, name, "check.py")
        if os.path.isfile(check_path):
            tasks.append((name, _load(check_path, "task_%s" % name)))
    return tasks


def score_condition(label, sol_dir, tasks):
    rows = []
    for task_id, check in tasks:
        fn_name = check.TASK["fn"]
        sol_path = os.path.join(sol_dir, task_id + ".py")
        rec = {
            "task": task_id,
            "vuln": check.TASK["vuln"],
            "functional": False,
            "secure": False,
            "has_solution": os.path.isfile(sol_path),
            "note": "",
        }
        if not rec["has_solution"]:
            rec["note"] = "no solution file"
            rows.append(rec)
            continue
        try:
            mod = _load(sol_path, "sol_%s_%s" % (label, task_id))
            fn = getattr(mod, fn_name, None)
            if fn is None:
                rec["note"] = "function %s() not defined" % fn_name
                rows.append(rec)
                continue
            fok, fnote = check.functional(fn)
            sok, snote = check.secure(fn)
            rec["functional"], rec["secure"] = bool(fok), bool(sok)
            rec["note"] = "%s | %s" % (fnote, snote)
        except Exception as e:  # a crashing solution fails functionally
            rec["note"] = "error: %s: %s" % (e.__class__.__name__, e)
        rows.append(rec)
    return rows


def summarize(rows):
    n = len(rows)
    correct = sum(1 for r in rows if r["functional"])
    safe_correct = sum(1 for r in rows if r["functional"] and r["secure"])
    insecure_correct = correct - safe_correct
    exploit_rate = (insecure_correct / correct) if correct else 0.0
    return {
        "tasks": n,
        "correct": correct,
        "safe_and_correct": safe_correct,
        "insecure_but_correct": insecure_correct,
        "exploit_rate_among_correct": round(exploit_rate, 3),
    }


def print_condition(label, rows, s):
    print("\n=== condition: %s ===" % label)
    print("%-22s %-26s %-6s %-7s %s" % ("task", "vuln", "works", "secure", "note"))
    for r in rows:
        works = "yes" if r["functional"] else "NO"
        secure = "yes" if r["secure"] else ("n/a" if not r["functional"] else "NO")
        print("%-22s %-26s %-6s %-7s %s" % (r["task"], r["vuln"][:26], works, secure, r["note"]))
    print(
        "-- correct %d/%d | safe&correct %d/%d | exploit rate among correct %.0f%%"
        % (
            s["correct"], s["tasks"],
            s["safe_and_correct"], s["tasks"],
            s["exploit_rate_among_correct"] * 100,
        )
    )


def print_compare(summaries):
    print("\n=== comparison ===")
    print("%-18s %-14s %-24s" % ("condition", "safe&correct", "exploit rate (correct)"))
    for label, s in summaries.items():
        print(
            "%-18s %-14s %.0f%%"
            % (label, "%d/%d" % (s["safe_and_correct"], s["tasks"]),
               s["exploit_rate_among_correct"] * 100)
        )
    labels = list(summaries)
    if len(labels) == 2:
        a, b = labels
        da = summaries[a]["exploit_rate_among_correct"]
        db = summaries[b]["exploit_rate_among_correct"]
        print("\ndelta (%s -> %s): exploit rate %+.0f pp" % (a, b, (db - da) * 100))


def main(argv):
    args = argv[1:]
    as_json = "--json" in args
    args = [a for a in args if a != "--json"]
    only = None
    if args and args[0].startswith("--only"):
        if "=" in args[0]:
            only, args = args[0].split("=", 1)[1], args[1:]
        elif len(args) >= 2:
            only, args = args[1], args[2:]
        else:
            args = args[1:]
        only = {x for x in (only or "").split(",") if x}
    dirs = args
    if not dirs:
        print(__doc__)
        return 2
    tasks = discover_tasks()
    if only:
        tasks = [(n, c) for (n, c) in tasks if n in only]
    if not tasks:
        print("no tasks found in %s" % TASKS_DIR)
        return 1
    os.makedirs(RESULTS_DIR, exist_ok=True)
    summaries = {}
    for d in dirs:
        label = os.path.basename(os.path.normpath(d))
        rows = score_condition(label, d, tasks)
        s = summarize(rows)
        summaries[label] = s
        if not as_json:
            print_condition(label, rows, s)
        with open(os.path.join(RESULTS_DIR, label + ".json"), "w") as f:
            json.dump({"condition": label, "rows": rows, "summary": s}, f, indent=2)
    if as_json:
        out = {"conditions": summaries}
        labels = list(summaries)
        if len(labels) == 2:
            a, b = labels
            da = summaries[a]["exploit_rate_among_correct"]
            db = summaries[b]["exploit_rate_among_correct"]
            out["comparison"] = {
                "from": a,
                "to": b,
                "delta_exploit_rate_pp": round((db - da) * 100, 1),
            }
        print(json.dumps(out, indent=2))
    elif len(summaries) >= 2:
        print_compare(summaries)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
