"""freeze_check.py - guards the frozen feature extractor.

  python capture\\freeze_check.py --write   (only when we freeze ON PURPOSE)
  python capture\\freeze_check.py           (check: did a frozen file change?)

The three files below decide the feature values. Their fingerprints (SHA-256)
are saved in capture\\frozen_hashes.json. Line endings are ignored.
If a check says CHANGED, do not collect data. Tell Claude first.
"""
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
FROZEN_FILES = ["features.py", "flow_builder.py", "sniffer.py"]
RECORD = HERE / "frozen_hashes.json"


def fingerprint(path):
    data = path.read_bytes().replace(b"\r\n", b"\n")
    return hashlib.sha256(data).hexdigest()


def main():
    current = {name: fingerprint(HERE / name) for name in FROZEN_FILES}
    if "--write" in sys.argv:
        RECORD.write_text(json.dumps(current, indent=2) + "\n", encoding="utf-8")
        print("FROZEN. Saved fingerprints to", RECORD.name)
        for name, h in current.items():
            print("  %-16s %s" % (name, h[:16]))
        return 0
    if not RECORD.exists():
        print("Not frozen yet. Run with --write first.")
        return 2
    saved = json.loads(RECORD.read_text(encoding="utf-8"))
    ok = True
    for name in FROZEN_FILES:
        same = saved.get(name) == current[name]
        ok = ok and same
        print("%-8s %s" % ("same" if same else "CHANGED", name))
    print()
    print("STILL FROZEN" if ok else "NOT FROZEN ANY MORE: a frozen file changed")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())