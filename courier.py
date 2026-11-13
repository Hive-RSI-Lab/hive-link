#!/usr/bin/env python3
"""hive-link courier: carries signed envelope files between two Hives that cannot reach each other directly.

It is a dumb carrier. It never signs, never reads keys, and never runs what it carries.
The receiving Hive checks every signature, so the courier can drop or delay a message but can't forge one.
It still checks shape, names, sizes and the from/to pair, so a bad file stays where it is and never reaches the other side.
Stdlib only, so it can run from a root-owned copy without the module installed.
Run it as the owner of each spool (runuser/setpriv), never as root on a dir another account can write: it works through
one dir fd and never follows links, but dropping to the owner is the first guard.

  courier.py pack   DIR --from A --to B     print a bundle of DIR's envelopes from A to B, removing them (at most once)
  courier.py unpack DIR --from A --to B     read a bundle on stdin and write its envelopes into DIR
  courier.py swap --inbox I --outbox O --here B --peer A
                                            the far end in one call: unpack stdin (A->B) into I, then pack O (B->A) to stdout

One round over ssh, run every minute by whoever owns the route:
  courier.py pack /var/lib/h2-link/h3/out --from h2 --to h3 \\
    | ssh ROUTE 'as h3: courier.py swap --inbox ~/.hive-link/inbox --outbox ~/.hive-link/outbox/h2 --here h3 --peer h2' \\
    | courier.py unpack /var/lib/h2-link/h3/in --from h3 --to h2
"""
import argparse, json, os, re, stat, sys

NAME = re.compile(r"^[A-Za-z0-9._-]{1,100}\.json$")
HIVE = re.compile(r"^[a-z0-9][a-z0-9-]{0,30}$")
MAX_FILE = 128 * 1024
MAX_TOTAL = 4 * 1024 * 1024
MAX_FILES = 200
FIELDS1 = {"v", "from_hive", "to_hive", "thread", "text", "ts", "nonce", "sig"}
FIELDS2 = {"v", "kind", "from_hive", "to_hive", "thread", "body", "ts", "nonce", "sig"}


def valid(env, frm, to):
    if not isinstance(env, dict): return False
    if env.get("v") == 1: ok = set(env) == FIELDS1
    elif env.get("v") == 2: ok = set(env) == FIELDS2 and env.get("kind") in ("msg", "ping", "req", "res")
    else: return False
    return ok and env.get("from_hive") == frm and env.get("to_hive") == to and isinstance(env.get("sig"), str)


def opendir(d, create=False):
    """One fd for the spool dir, opened without following a link. Every open, unlink and rename below goes through it
    (dir_fd=), so swapping the dir, or a file in it, for a symlink mid-round can't make the courier touch anything else."""
    if create:
        os.makedirs(d, 0o770, exist_ok=True)
    return os.open(d, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)


def load(dfd, n):
    fd = os.open(n, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode): raise OSError("not a regular file")
        data = f.read(MAX_FILE + 1)
    return data


def rm(dfd, n):
    try: os.unlink(n, dir_fd=dfd)
    except OSError: pass


def pack(d, frm, to, out=sys.stdout):
    files, total = {}, 0
    try: dfd = opendir(d)
    except OSError: dfd = None
    if dfd is not None:
        try:
            for n in sorted(os.listdir(dfd)):
                if len(files) >= MAX_FILES: break
                if not NAME.match(n): continue
                try:
                    st = os.stat(n, dir_fd=dfd, follow_symlinks=False)
                    if not stat.S_ISREG(st.st_mode): continue
                    data = load(dfd, n)
                    if len(data) > MAX_FILE: rm(dfd, n); continue  # never carried; the sender's own cap is lower
                    if total + len(data) > MAX_TOTAL: break
                    env = json.loads(data)
                except (OSError, ValueError):
                    continue  # maybe half-written; the next round tries again
                except RecursionError:
                    rm(dfd, n); continue
                if not valid(env, frm, to): rm(dfd, n); continue
                files[n] = env; total += len(data)
        except BaseException:
            os.close(dfd); raise
    out.write(json.dumps({"courier": 1, "from": frm, "to": to, "files": files}))
    out.flush()
    if dfd is not None:
        for n in files: rm(dfd, n)  # at most once: gone from the outbox once it has been handed to the pipe
        os.close(dfd)
    return len(files)


def unpack(d, frm, to, data):
    if not data.strip(): return 0
    if len(data) > MAX_TOTAL + 64 * 1024: raise SystemExit("bundle too large")
    try: b = json.loads(data)
    except (ValueError, RecursionError): raise SystemExit("not a bundle")
    if not isinstance(b, dict) or b.get("courier") != 1 or b.get("from") != frm or b.get("to") != to or not isinstance(b.get("files"), dict):
        raise SystemExit("not a bundle for this pair")
    if len(b["files"]) > MAX_FILES: raise SystemExit("too many files")
    dfd = opendir(d, create=True)
    n = 0
    try:
        for name, env in b["files"].items():
            blob = json.dumps(env)
            if not isinstance(name, str) or not NAME.match(name) or len(blob) > MAX_FILE or not valid(env, frm, to): continue
            try: os.stat(name, dir_fd=dfd, follow_symlinks=False); continue  # already there (or something in its place)
            except FileNotFoundError: pass
            tmp = "." + name + ".tmp"
            rm(dfd, tmp)
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o660, dir_fd=dfd)
            with os.fdopen(fd, "w") as f: f.write(blob)
            os.rename(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
            n += 1
    finally:
        os.close(dfd)
    return n


def main(argv=None):
    ap = argparse.ArgumentParser(prog="courier.py", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = ap.add_subparsers(dest="cmd", required=True)
    for c in ("pack", "unpack"):
        a = sp.add_parser(c); a.add_argument("dir"); a.add_argument("--from", dest="frm", required=True); a.add_argument("--to", required=True)
    a = sp.add_parser("swap"); a.add_argument("--inbox", required=True); a.add_argument("--outbox", required=True)
    a.add_argument("--here", required=True); a.add_argument("--peer", required=True)
    o = ap.parse_args(argv)
    for h in (getattr(o, "frm", None), getattr(o, "to", None), getattr(o, "here", None), getattr(o, "peer", None)):
        if h is not None and not HIVE.match(h): raise SystemExit("bad hive name")
    os.umask(0o007)
    if o.cmd == "pack": n = pack(o.dir, o.frm, o.to); print(f"courier: packed {n}", file=sys.stderr)
    elif o.cmd == "unpack": n = unpack(o.dir, o.frm, o.to, sys.stdin.read()); print(f"courier: delivered {n}", file=sys.stderr)
    else:
        n = unpack(os.path.expanduser(o.inbox), o.peer, o.here, sys.stdin.read())
        m = pack(os.path.expanduser(o.outbox), o.here, o.peer)
        print(f"courier: delivered {n}, packed {m}", file=sys.stderr)


if __name__ == "__main__": main()
