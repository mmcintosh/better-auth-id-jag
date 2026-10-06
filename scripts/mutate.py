# Break-it-once runner. Each entry in a JSON list is one mutation:
#   {name, file, a, b, paths}                 one edit: replace `a` with `b` (first occurrence) in `file`
#   {name, edits: [{file, a, b}, ...], paths} several edits applied together (a guard pair)
#   "expect": "survive", "why": "..."         a known, explained survivor (equivalent, or half of a pair)
# It applies the mutation, runs the Node test project on `paths`, records CAUGHT or SURVIVED, and
# restores every file. Exit status 1 if any mutation survives unexpectedly, is caught when it was
# expected to survive, or no longer matches the code (PATTERN NOT FOUND): the list tracks the code.
# Usage: python3 scripts/mutate.py <list.json> [<list.json> ...]
import json, subprocess, sys

bad = 0
counts = {"CAUGHT": 0, "SURVIVED (expected)": 0}
for path in sys.argv[1:]:
  for m in json.load(open(path)):
    name = m["name"]
    edits = m.get("edits") or [{"file": m["file"], "a": m["a"], "b": m["b"]}]
    originals = {}
    try:
      missing = False
      for e in edits:
        src = originals.get(e["file"]) or open(e["file"]).read()
        originals.setdefault(e["file"], src)
        current = open(e["file"]).read()
        if e["a"] not in current:
          missing = True
          break
        open(e["file"], "w").write(current.replace(e["a"], e["b"], 1))
      if missing:
        print(f"## {name}: PATTERN NOT FOUND")
        bad += 1
        continue
      r = subprocess.run(["npx", "vitest", "run", "--project", "node", *m.get("paths", [])], capture_output=True, text=True, timeout=900)
      out = r.stdout + r.stderr
      fails = sorted(set(l.strip()[:150] for l in out.splitlines() if l.strip().startswith("FAIL ")))
      summ = [l.strip() for l in out.splitlines() if l.strip().startswith("Tests ")]
      caught = bool(fails) or r.returncode != 0
      expected_survivor = m.get("expect") == "survive"
      if caught and not expected_survivor:
        verdict = "CAUGHT"; counts["CAUGHT"] += 1
      elif not caught and expected_survivor:
        verdict = "SURVIVED (expected)"; counts["SURVIVED (expected)"] += 1
      elif caught:
        verdict = "CAUGHT, BUT EXPECTED TO SURVIVE: update the list"; bad += 1
      else:
        verdict = "SURVIVED"; bad += 1
      print(f"## {name}: {verdict} {summ[-1] if summ else ''}")
      for x in fails[:4]: print("   ", x)
    finally:
      for f, src in originals.items(): open(f, "w").write(src)

print(f"\n{counts['CAUGHT']} caught, {counts['SURVIVED (expected)']} expected survivors, {bad} problems")
sys.exit(1 if bad else 0)
