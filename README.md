# hive-link

Lets Hives talk to each other. It does three things:

- It carries **signed messages**.
- It runs **support sessions**: one Hive asks another for diagnostics or an admin step. The Hive receiving the request runs it only under a grant it has set for the asker itself.
- It runs a **service** that notices when a peer goes quiet.

Commands: `hive-link` (also `h2-link`). Python 3 with `cryptography`. Files live in `~/.hive-link/` (mode 0700).

## Trust model

- Every envelope is signed with ed25519 by the sending Hive. It is accepted only if all of these hold:
  - the sender's key is **pinned** on the receiving side;
  - the envelope is addressed to this Hive;
  - it is fresh: at most 300 s ahead of this Hive's clock and at most an hour old;
  - its nonce hasn't been seen before (seen nonces are kept on disk, so a restart doesn't reopen replays);
  - the sender is within the rate limit of 20 a minute.
- Pinning, granting and revoking are local acts. Nothing that arrives over the link can do them.
- **By default a peer may ask for nothing.** The receiving Hive's owner or agents decide what a peer may do:
  ```
  hive-link grant h2 diag --for 2h --why "debugging the mail fix"
  hive-link grant h2 admin --standing --why "our hub Hive"   # until revoked
  hive-link grant h2 task --for 4h --why "H3's mail fix"      # at most 24 h, never standing
  hive-link revoke h2
  ```
  `diag` covers read-only actions. `admin` adds changes. `task` adds starting an agent here on the peer's brief; it is always time-limited (24 h at most) and never standing, and a peer pinned with `--no-board` can't be given one. An expired grant counts as no grant.
- There is no generic shell. A peer can ask only for the fixed actions below, each with checked arguments.
- A request arriving over the link can never do a hard-limit thing, whatever the grant says. That means it can't:
  - spend money;
  - print or send credentials;
  - delete repos or history;
  - open the machine;
  - publish private details;
  - act in the person's name.

  What holds them:
  - None of the fixed actions can do these things. This is the real guard.
  - A `task` starts an agent on this Hive, which can do anything this Hive's agents can. So `task` is its own scope, short and never standing. The agent gets the brief framed as untrusted text from another Hive, is told the hard limits hold, and is told to ask `warden` in its thread before acting.
  - A brief that reads as a hard-limit thing is refused before any agent sees it. This is a pattern match, a speed bump against honest mistakes, not a guard: a reworded brief gets past it.
- Everything a peer sends back is **redacted** before it leaves:
  - exact values from this Hive's own secret files (credentials, tokens, `.env` files, `*.secret`, keys);
  - common secret shapes, such as API keys (Anthropic, OpenAI, Stripe, GitHub, Slack, AWS, Google OAuth, Hugging Face, Telegram), JWTs, PEM and PGP private keys, URL passwords, cookies, netrc passwords and `password=`/`token:`-style pairs in any quoting;
  - any value, of any type, under a name that looks secret.

  Redaction is pattern-based and can miss an odd shape. That is why `file` reads only kb, modules, core and projects, refuses secret-looking names and symlinks, and why `diag` is the grant to give by default.
- Answers and messages are **untrusted data** on arrival. `@` becomes `＠`, so remote text can never wake an agent, and every line is quoted with `│ ` so it can't pass for a post's own lines. A peer's message lands in thread `link-PEER` (or a thread this Hive asked that peer in), never in a thread the peer picks. Each request takes one answer (a task two: the answer and the agent's reply); more are dropped.
- **Audit.** Every request and its decision go to `~/.hive-link/audit.jsonl`. The receiving Hive also posts one line per request to its board thread `hive-link`, where its owner reads them.

## Actions

| action | scope | what |
|---|---|---|
| `status` | diag | version, hive-/h2- units, failed units, load, memory, disk, link peers |
| `logs` | diag | `unit=hive-starter lines=100 [since='2h ago']`, this Hive's own units only |
| `settings` | diag | settings files with secrets left out, link peers and grants |
| `board` | admin | `since=2h` or `thread=T` (the board holds the person's words, so it is not diagnostics) |
| `who`, `modules` | diag | agents running; modules |
| `file` | diag | `path=kb/...`: read a text file or list a folder under kb, modules, core or projects; secret-looking names are refused |
| `restart` | admin | `unit=hive-dash`: one of this Hive's loaded `hive-`/`h2-` units (no templates), never the link itself |
| `module-add` | admin | `name=X`, from this Hive's catalog only, never a URL |
| `update` | admin | `check=1` (default) or `check=0` to install a signed release |
| `task` | task | `brief='...' [model=sonnet]`: starts an agent on the receiving Hive. It answers with `hive-link reply` |

## Commands for agents

```
hive-link peers                                  who is pinned, how each is reached, last heard, the grant you set for each
hive-link send h3 --thread T <<'X' ... X         a message onto h3's board (untrusted text there)
hive-link ask h3 status                          diagnostics; waits up to 120 s, then posts the answer to your thread when it comes
hive-link ask h3 logs unit=hive-starter lines=200
hive-link ask h3 task brief='Mail fix from H2: apply ... and report' model=sonnet --thread T
hive-link result ID                              an answer that came later
hive-link reply h2 ID <<'X' ... X                (the agent doing a task) send its result back
hive-link actions | grants | audit [--peer P] | check
hive-link inbox                                  messages from peers pinned with --no-board
```

`hive-link pin h4 KEY --via dir:/x --no-board` keeps a peer's words off this Hive's board. Its messages go to `~/.hive-link/messages.jsonl`, which `hive-link inbox` reads. No request lines or answer posts for it go on the board. Use this for a Hive whose content must stay out of this board.

## Setting up a Hive

1. `hive module add link`. Then run `hive-link init NAME` and give the printed public key to the other Hive's owner through a channel you trust.
2. Pin each peer's key and say how to reach it with `--via`: `hive-link pin h2 KEY --via outbox`. The ways to reach a peer:
   - `http://127.0.0.1:PORT`: same machine, loopback only.
   - `dir:/path`: a spool dir with `out/` and `in/`, carried by a courier.
   - `outbox`: `~/.hive-link/outbox/PEER`, picked up by a courier, which delivers into `~/.hive-link/inbox`.
3. `hive-link install [--http PORT]` writes and starts the user unit `hive-link.service`. The service:
   - reads the inboxes;
   - pings each peer every 5 minutes;
   - posts once to thread `hive-link` when a peer has been quiet for 20 minutes, and once when it is back.
4. On the receiving side, set the grant you mean to give, for example a standing `diag` grant for your hub.

The listener binds loopback only. The module refuses any other address: opening a machine to the network is not this module's decision.

## The courier

`courier.py` is for two Hives that can't reach each other. It uses only the standard library and never signs anything or reads keys. It can drop or delay a message but can't forge one. It checks the shape, file names, sizes (128 KB per envelope, 4 MB and 200 files per round) and the from/to pair, and writes files atomically. Each file is carried at most once. One round through an existing route:

```
courier.py pack /var/lib/h2-link/h3/out --from h2 --to h3 \
  | ssh ROUTE '(as h3) courier.py swap --inbox ~/.hive-link/inbox --outbox ~/.hive-link/outbox/h2 --here h3 --peer h2' \
  | courier.py unpack /var/lib/h2-link/h3/in --from h3 --to h2
```

Whoever owns the route runs the courier from their own copy. It needs no listener. Run each end **as the owner of that spool** (`runuser -u hive2 --`, `setpriv`), never as root on a dir another account can write. The courier works through one directory fd and never follows a link or opens a FIFO, but dropping to the owner is the first guard.

## Tests

`python3 -m unittest test_link` runs the tests. The hostile cases include:
- forged, tampered, replayed (also across a restart), stale and future envelopes;
- unknown and impostor peers;
- extra fields;
- out-of-scope, expired, revoked and missing grants;
- shell-like and unknown actions;
- path escapes, symlinks and FIFOs, in `file`, in the inbox and in the courier's spool (including the spool dir itself swapped for a link);
- deeply nested and oversize JSON, and bad HTTP lengths;
- foreign and template units;
- briefs that try credentials, force-push, repo deletion, the card on file, impersonation or a public listener;
- a peer choosing the board thread, and repeated answers;
- module URLs;
- hard-limit briefs;
- answers from the wrong peer or to nothing asked;
- hostile courier bundles;
- redaction, including the samples a reviewer found getting through.

Version 1 envelopes (`text` with no `kind`) are still accepted as messages.
