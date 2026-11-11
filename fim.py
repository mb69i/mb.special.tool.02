#!/usr/bin/env python3
"""fim.py - small file integrity monitor. Stdlib only, Python 3.9+.

    python fim.py init /etc /usr/local/bin     # record a baseline
    python fim.py check                        # compare the tree against it
    python fim.py update                       # accept current state as the new baseline
    python fim.py watch -i 60                  # poll and report changes

Exit codes: 0 clean, 1 changes found, 2 error (unreadable paths, missing or tampered baseline).

Set FIM_KEY to seal the baseline with an HMAC. Without a key the seal only catches
accidental damage: anyone who can edit the baseline can forge it, so keep it read-only.
"""
import argparse
import fnmatch
import hashlib
import hmac
import json
import os
import stat
import sys
import time

VERSION = 2
CHUNK = 1 << 20
CHANGES = ("added", "removed", "modified", "attrs")
MARK = {"added": "+", "removed": "-", "modified": "M", "attrs": "A", "unreadable": "?"}


def die(msg):
    print(msg, file=sys.stderr)
    sys.exit(2)


def file_hash(path, algo):
    h = hashlib.new(algo)
    with open(path, "rb", buffering=0) as f:
        for block in iter(lambda: f.read(CHUNK), b""):
            h.update(block)
    return h.hexdigest()


def seal(recs, meta):
    """Fingerprint of the records and the settings, so neither can be edited quietly."""
    body = {"meta": {k: v for k, v in meta.items() if k != "seal"}, "records": recs}
    blob = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    if meta.get("keyed"):
        return hmac.new(os.environ.get("FIM_KEY", "").encode(), blob, hashlib.sha256).hexdigest()
    return hashlib.sha256(blob).hexdigest()


def excluded(path, pats):
    base = os.path.basename(path)
    return any(fnmatch.fnmatch(path, p) or fnmatch.fnmatch(base, p) for p in pats)


def hidden(path, pats, roots):
    """True when path, or a folder above it inside the monitored tree, matches a pattern."""
    while path not in roots:
        if excluded(path, pats):
            return True
        parent = os.path.dirname(path)
        if parent == path:
            return False
        path = parent
    return False


def walk(roots, pats, follow, ignore, info):
    """Yield every path under the roots, the roots and all directories included."""
    seen = set()
    for root in roots:
        stack = [root]
        while stack:
            p = stack.pop()
            yield p
            try:
                st = os.stat(p) if follow else os.lstat(p)
            except OSError:
                continue                          # record() reports it
            if not stat.S_ISDIR(st.st_mode):
                continue
            if follow:                            # symlink loops: walk each real directory once
                key = (st.st_dev, st.st_ino)
                if key in seen:
                    continue
                seen.add(key)
            try:
                names = sorted(os.listdir(p))
            except OSError as e:
                info["blind"][p] = e.strerror or str(e)
                continue
            for name in reversed(names):
                child = os.path.join(p, name)
                if child in ignore:
                    continue
                if excluded(child, pats):
                    info["excluded"] += 1
                    continue
                stack.append(child)


def record(path, algo, follow, old, fast):
    try:
        st = os.stat(path) if follow else os.lstat(path)
    except OSError:
        st = os.lstat(path)                       # broken symlink under --follow
    r = {"mode": stat.S_IMODE(st.st_mode), "uid": st.st_uid, "gid": st.st_gid}
    if stat.S_ISDIR(st.st_mode):
        r["kind"] = "dir"
    elif stat.S_ISLNK(st.st_mode):
        r["kind"], r["link"] = "link", os.readlink(path)
    elif stat.S_ISREG(st.st_mode):
        r.update(kind="file", size=st.st_size, mtime=st.st_mtime_ns)
        same = (fast and old and old.get("kind") == "file" and "hash" in old
                and old.get("size") == r["size"] and old.get("mtime") == r["mtime"])
        if same:
            r["hash"] = old["hash"]
        else:
            try:
                r["hash"] = file_hash(path, algo)
            except OSError as e:
                r["unreadable"] = e.strerror or str(e)
    else:
        r["kind"] = "special"
    return r


def scan(meta, ignore, fast, old):
    info = {"excluded": 0, "blind": {}}
    recs = {}
    for p in walk(meta["roots"], meta["skip"], meta["follow"], ignore, info):
        try:
            recs[p] = record(p, meta["algo"], meta["follow"], old.get(p), fast)
        except FileNotFoundError:
            continue                              # vanished while we were looking
        except OSError as e:
            recs[p] = {"kind": "unknown", "unreadable": e.strerror or str(e)}
    for d, why in info["blind"].items():          # folders we could not list
        if d in recs:
            recs[d]["unreadable"] = why
    return recs, info


def compare(old, new, blind=()):
    under_blind = tuple(d.rstrip(os.sep) + os.sep for d in blind)
    o, n = set(old), set(new)
    out = {"added": sorted(n - o),
           "removed": sorted(p for p in o - n if not p.startswith(under_blind)),
           "modified": [], "attrs": [],
           "unreadable": [[p, new[p]["unreadable"]] for p in sorted(n) if "unreadable" in new[p]]}
    for p in sorted(o & n):
        a, b = old[p], new[p]
        why = []
        if a.get("kind") != b.get("kind"):
            why.append(f"type {a.get('kind')} -> {b.get('kind')}")
        elif b.get("kind") == "file" and "hash" in b:
            if "hash" not in a:
                why.append("readable now, no baseline hash yet")
            elif a["hash"] != b["hash"]:
                why.append("content")
                if a.get("mtime") == b.get("mtime"):
                    why.append("mtime unchanged - timestamp preserved")
        elif b.get("kind") == "link" and a.get("link") != b.get("link"):
            why.append(f"symlink {a.get('link')} -> {b.get('link')}")
        if why:
            out["modified"].append([p, "; ".join(why)])
            continue
        for k, label in (("mode", "mode"), ("uid", "owner"), ("gid", "group")):
            if a.get(k) != b.get(k):
                va, vb = a.get(k), b.get(k)
                if k == "mode":
                    va, vb = (format(v, "04o") if isinstance(v, int) else v for v in (va, vb))
                why.append(f"{label} {va} -> {vb}")
        if why:
            out["attrs"].append([p, "; ".join(why)])
    return out


def load(path):
    try:
        with open(path) as f:
            d = json.load(f)
        recs, meta = d["records"], d["meta"]
    except (OSError, ValueError, KeyError, TypeError) as e:
        die(f"cannot read baseline {path}: {e}")
    ok = (isinstance(recs, dict) and isinstance(meta, dict)
          and all(isinstance(meta.get(k), list) for k in ("roots", "skip")))
    if not ok:
        die(f"baseline {path} is malformed")
    if meta.get("version") != VERSION:
        die(f"baseline {path} was written by another fim.py version - re-create it with: init --force")
    key = os.environ.get("FIM_KEY")
    if meta.get("keyed") and not key:
        die(f"baseline {path} is sealed with a key, but FIM_KEY is not set - cannot verify it")
    if key and not meta.get("keyed"):
        die(f"FIM_KEY is set, but baseline {path} is not sealed with a key (possible downgrade) - "
            "re-create it with: init --force")
    if not hmac.compare_digest(seal(recs, meta), str(meta.get("seal", ""))):
        die(f"baseline {path} does not match its seal - it was changed outside this tool"
            + (" or FIM_KEY is wrong" if key else ""))
    return recs, meta


def save(path, recs, meta):
    meta["keyed"] = bool(os.environ.get("FIM_KEY"))
    meta["saved"] = time.strftime("%Y-%m-%d %H:%M:%S")
    meta["seal"] = seal(recs, meta)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"meta": meta, "records": recs}, f, separators=(",", ":"), sort_keys=True)
    os.replace(tmp, path)
    os.chmod(path, 0o600)


def count(recs):
    dirs = sum(1 for r in recs.values() if r.get("kind") == "dir")
    return len(recs) - dirs, dirs


def report(diff, old, new, info, secs, limit):
    files, dirs = count(new)
    changes = sum(len(diff[k]) for k in CHANGES)
    bad = f", {len(diff['unreadable'])} unreadable" if diff["unreadable"] else ""
    print(f"\n== {files} files + {dirs} dirs, {secs}s, {changes} change(s){bad} ==")
    for kind in CHANGES + ("unreadable",):
        items = diff[kind]
        for item in items[:limit]:
            p, why = (item, "") if isinstance(item, str) else item
            rec = (old if kind == "removed" else new).get(p, {})
            shown = p + os.sep if rec.get("kind") == "dir" else p
            if kind == "unreadable":
                why = f"unreadable: {why}"
            print(f"{MARK[kind]} {shown}" + (f"  ({why})" if why else ""))
        if len(items) > limit:
            print(f"  ... and {len(items) - limit} more {kind}")
    if info["excluded"]:
        print(f"note: {info['excluded']} path(s) skipped by -x patterns")
    return changes


def main():
    ap = argparse.ArgumentParser(description="Small file integrity monitor.")
    ap.add_argument("mode", choices=["init", "check", "update", "watch"])
    ap.add_argument("paths", nargs="*", help="files or directories (init only)")
    ap.add_argument("-b", "--baseline", default="fim-baseline.json", help="baseline file")
    ap.add_argument("-x", "--exclude", action="append", default=[],
                    help="glob to skip, repeatable (nothing is skipped by default; every exclusion is a blind spot)")
    ap.add_argument("--algo", default="sha256", help="hash algorithm (default sha256)")
    ap.add_argument("--follow", action="store_true", help="follow symlinks")
    ap.add_argument("--fast", action="store_true",
                    help="reuse the stored hash when size and mtime match (misses timestamp-preserving edits)")
    ap.add_argument("--force", action="store_true", help="init: replace an existing baseline")
    ap.add_argument("-i", "--interval", type=int, default=60, help="watch interval in seconds")
    ap.add_argument("-n", "--max", type=int, default=50, help="lines printed per category")
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("-q", "--quiet", action="store_true", help="print nothing when clean")
    a = ap.parse_args()
    if a.algo not in hashlib.algorithms_available or a.algo.startswith("shake"):
        die(f"unknown hash algorithm {a.algo}; try: sha256 sha512 blake2b")
    base = os.path.abspath(a.baseline)
    ignore = {base, base + ".tmp"}                # never report the baseline itself

    if a.mode == "init":
        if not a.paths:
            die("init needs at least one path")
        missing = [p for p in a.paths if not os.path.lexists(p)]
        if missing:
            die("not found: " + ", ".join(missing))
        if os.path.lexists(a.baseline) and not a.force:
            die(f"{a.baseline} already exists - use --force to replace it")
        meta = {"version": VERSION, "roots": [os.path.abspath(p) for p in a.paths],
                "skip": a.exclude, "algo": a.algo, "follow": a.follow}
        t0 = time.time()
        recs, info = scan(meta, ignore, False, {})
        save(a.baseline, recs, meta)
        files, dirs = count(recs)
        print(f"baseline: {files} files + {dirs} dirs in {round(time.time() - t0, 1)}s -> {a.baseline}")
        bad = [(p, r["unreadable"]) for p, r in sorted(recs.items()) if "unreadable" in r]
        for p, why in bad[:a.max]:
            print(f"? {p}  (unreadable: {why})")
        if len(bad) > a.max:
            print(f"  ... and {len(bad) - a.max} more unreadable")
        if info["excluded"]:
            print(f"note: {info['excluded']} path(s) skipped by -x patterns")
        if not meta["keyed"]:
            print("note: FIM_KEY is not set, so anyone who can edit this baseline can forge it",
                  file=sys.stderr)
        return 2 if bad else 0

    old, meta = load(a.baseline)
    if a.exclude:                                 # extra patterns apply to the stored records too
        roots = set(meta["roots"])
        meta["skip"] = meta["skip"] + a.exclude
        old = {p: r for p, r in old.items() if not hidden(p, a.exclude, roots)}

    def cycle(prev):
        t0 = time.time()
        recs, info = scan(meta, ignore, a.fast, prev)
        return recs, info, compare(prev, recs, info["blind"]), round(time.time() - t0, 1)

    if a.mode in ("check", "update"):
        recs, info, diff, secs = cycle(old)
        changes = sum(len(diff[k]) for k in CHANGES)
        if a.mode == "update":
            save(a.baseline, recs, meta)
        if a.json:
            files, dirs = count(recs)
            out = {"files": files, "dirs": dirs, "seconds": secs, "excluded": info["excluded"], **diff}
            if a.mode == "update":
                out["baseline_updated"] = True
            print(json.dumps(out, indent=2))
        else:
            if changes or diff["unreadable"] or not a.quiet:
                report(diff, old, recs, info, secs, a.max)
            if a.mode == "update":
                print(f"baseline updated ({changes} change(s) accepted)")
        if a.mode == "update":
            return 2 if diff["unreadable"] else 0
        return 1 if changes else 2 if diff["unreadable"] else 0

    while True:  # watch
        recs, info, diff, secs = cycle(old)
        if sum(len(diff[k]) for k in CHANGES):
            print(time.strftime("[%H:%M:%S]"), end="")
            report(diff, old, recs, info, secs, a.max)
            sys.stdout.flush()
        elif not a.quiet:
            files, dirs = count(recs)
            bad = f", {len(diff['unreadable'])} unreadable" if diff["unreadable"] else ""
            print(f"[{time.strftime('%H:%M:%S')}] clean ({files} files + {dirs} dirs{bad}, {secs}s)", flush=True)
        old = recs  # already reported; only report each change once
        time.sleep(a.interval)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
    except BrokenPipeError:  # piped into head, less, etc.
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(0)
