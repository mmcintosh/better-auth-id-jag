# Break-it-once runner: applies each mutation in a JSON list ({name, file, a, b, paths}), runs the
# Node test project, records CAUGHT or SURVIVED, and restores the file. Usage: python3 scripts/mutate.py <list.json>
import subprocess, sys, json
muts = json.load(open(sys.argv[1]))
for m in muts:
  name, f, a, b = m["name"], m["file"], m["a"], m["b"]
  orig = open(f).read()
  if a not in orig:
    print(f"## {name}: PATTERN NOT FOUND"); continue
  open(f,'w').write(orig.replace(a,b,1))
  try:
    r = subprocess.run(["npx","vitest","run","--project","node", *m.get("paths",[])],capture_output=True,text=True,timeout=600)
    out = r.stdout + r.stderr
    fails = sorted(set(l.strip()[:150] for l in out.splitlines() if l.strip().startswith("FAIL ")))
    summ = [l.strip() for l in out.splitlines() if l.strip().startswith("Tests ")]
    print(f"## {name}: {'CAUGHT' if fails else 'SURVIVED'} {summ[-1] if summ else ''}")
    for x in fails[:4]: print("   ", x)
  finally:
    open(f,'w').write(orig)
