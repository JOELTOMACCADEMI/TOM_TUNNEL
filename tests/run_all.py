#!/usr/bin/env python3
"""Runs every test without needing pytest: unittest classes + plain `test_*` functions
(supports the `tmp_path` fixture used by tests/test_v2raydns_integration.py)."""
import importlib.util, inspect, sys, tempfile, traceback, unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
failed = total = 0
for f in sorted(HERE.glob("test_*.py")):
    spec = importlib.util.spec_from_file_location(f.stem, f)
    mod = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(HERE))
    spec.loader.exec_module(mod)
    suite = unittest.defaultTestLoader.loadTestsFromModule(mod)
    res = unittest.TextTestRunner(verbosity=0, stream=open("/dev/null", "w")).run(suite)
    total += res.testsRun; failed += len(res.failures) + len(res.errors)
    for t, tb in res.failures + res.errors:
        print("FAIL", t, "\n", tb)
    for name, fn in inspect.getmembers(mod, inspect.isfunction):
        if not name.startswith("test_") or fn.__module__ != mod.__name__:
            continue
        total += 1
        try:
            with tempfile.TemporaryDirectory() as d:
                fn(Path(d)) if "tmp_path" in inspect.signature(fn).parameters else fn()
        except Exception:
            failed += 1; print("FAIL", f.name, name); traceback.print_exc()
    print(f"{f.name}: done")
print(f"\nTOTAL {total} tests, {failed} failed")
sys.exit(1 if failed else 0)
