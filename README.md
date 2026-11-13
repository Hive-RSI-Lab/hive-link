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
  hive-link revoke h2
  ```
  `diag` covers read-only actions. `admin` adds changes. An expired grant counts as no grant.
- There is no generic shell. A peer can ask only for the fixed actions below, each with checked arguments.
- A request arriving over the link can never do a hard-limit thing, whatever the grant says. That means it can't:
  - spend money;
  - print or send credentials;
  - delete repos or history;
  - open the machine;
  - publish private details;
  - act in the person's name.

  These limits are enforced in three ways:
  - None of the actions can do these things.
  - A `task` brief that reads as one of them is refused before any agent sees it.
  - The agent a task starts is told the limits hold.
- Everything a peer sends back is **redacted** before it leaves:
  - exact values from this Hive's own secret files;
  - common secret shapes, such as API keys, tokens, JWTs, private keys, URL passwords and `token=` pairs;
  - any setting whose name looks secret.
- Answers and messages are **untrusted data** on arrival. `@` becomes `＠`, so remote text can never wake an agent.
- **Audit.** Every request and its decision go to `~/.hive-link/audit.jsonl`. The receiving Hive also posts one line per request to its board thread `hive-link`, where its owner reads them.

## Actions

| action | scope | what |
|---|---|---|
| `status` | diag | version, hive-/h2- units, failed units, load, memory, disk, link peers |
| `logs` | diag | `unit=hive-starter lines=100 [since='2h ago']`, this Hive's own units only |
| `settings` | diag | settings files with secrets left out, link peers and grants |
| `board` | diag | `since=2h` or `thread=T` |
| `who`, `modules` | diag | agents running; modules |
| `file` | diag | `path=kb/...`: read a text file or list a folder under kb, modules, core or projects; secret-looking names are refused |
| `restart` | admin | `unit=hive-dash`: one of this Hive's units, never the link itself |
| `module-add` | admin | `name=X`, from this Hive's catalog only, never a URL |
| `update` | admin | `check=1` (default) or `check=0` to install a signed release |
| `task` | admin | `brief='...' [model=sonnet]`: starts an agent on the receiving Hive. It answers with `hive-link reply` |

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
```

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

Whoever owns the route runs the courier from their own copy. It needs no listener.

## Tests

`python3 -m unittest test_link` runs the tests. The hostile cases include:
- forged, tampered, replayed (also across a restart), stale and future envelopes;
- unknown and impostor peers;
- extra fields;
- out-of-scope, expired, revoked and missing grants;
- shell-like and unknown actions;
- path escapes and symlinks;
- foreign units;
- module URLs;
- hard-limit briefs;
- answers from the wrong peer or to nothing asked;
- hostile courier bundles;
- redaction.

Version 1 envelopes (`text` with no `kind`) are still accepted as messages.
