import re

with open("benchmark/solutions/selftest_secure/webhook_event_apply.py", "r") as f:
    code = f.read()

code = code.replace(
    "event = json.loads(raw)\n    if not isinstance(event, dict):\n        return False\n    dispatch(event)",
    "try:\n        event = json.loads(raw)\n    except json.JSONDecodeError:\n        return False\n    if not isinstance(event, dict):\n        return False\n    dispatch(event)"
)

with open("benchmark/solutions/selftest_secure/webhook_event_apply.py", "w") as f:
    f.write(code)
