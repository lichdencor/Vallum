# Vallum

> *Vallum* (Latin): wall, Roman defensive palisade.

**Vallum** is a constrained firewall-policy compiler with a sandbox for AI
agents. It compiles a high-level Lisp DSL into validated, reproducible
nftables rulesets — and gives LLMs a **closed data contract** to respond to
incidents without ever touching firewall syntax.

## The central thesis

> **The AI never speaks nftables. It speaks data.**

| World | Who writes it | Format | Power |
|---|---|---|---|
| **Base policy** | Humans (git) | S-expressions | Full — compiled deterministically |
| **Dynamic rules** | AI agent or operator | Pure EDN/JSON, never evaluated | Allowlisted actions only, always with TTL |

An LLM produces *data* against a closed schema. It never invokes code and
never emits nftables syntax. What the compiler cannot express does not exist:
a prompt-injected model asking to `accept` traffic gets rejected by a spec
validator, not by hope.

## Requirements

- **JDK 17+** (`java.net.http` is used by the Gemini adapter; no SDKs added)
- **[Clojure CLI tools](https://clojure.org/guides/install_clojure)** 1.11+
- Linux + `nftables` at deployment time (compilation and testing work anywhere)

Dependencies are minimal: Clojure 1.12, cheshire (JSON), spec, test.check.
No HTTP client libraries — everything uses the JDK built-ins.

## Quickstart

Clone and run — no build step required (Clojure resolves dependencies on
first run):

```bash
git clone <repo-url> && cd vallum
clojure -M -m vallum.cli version
# vallum v0.1 (phase M5)

clojure -M -m vallum.cli compile examples/edge-host.lisp
```

Compile to a file:

```bash
clojure -M -m vallum.cli compile examples/edge-host.lisp -o ruleset.nft
sudo nft -f ruleset.nft   # apply on a real host
```

CLI commands:

| Command | Description |
|---|---|
| `compile <policy.lisp> [-o out.nft]` | Compile policy → nftables ruleset (stdout or `-o`) |
| `version` | Print version and active roadmap phase |
| `help` | Usage help |

Everything else (runtime, AI bridge, ingestion) is a **library API** used
from your own process or the REPL — see [Using Vallum with models](#using-vallum-with-models).

## Writing policies

A policy is a Lisp file (see `examples/edge-host.lisp`):

```lisp
(policy "edge-host"
  (zone wan {:iface "eth0"})
  (zone lan {:iface "eth1"})

  (service ssh {:proto :tcp :port 22})
  (service web {:proto :tcp :port [80 443]})

  (allow {:from :lan :to :wan})
  (allow {:from :wan :to :lan :service :web})
  (deny   {:from :wan :to :lan :service :ssh})

  ;; Containment sandbox for dynamic AI rules
  (sandbox containment
    {:actions     #{:drop-ip :rate-limit}
     :default-ttl "30m"
     :max-ttl     "24h"
     :max-active  50}))
```

DSL forms:

| Form | Meaning |
|---|---|
| `(policy "name" ...)` | Groups declarations |
| `(zone id {:iface "eth0"})` | Network zone bound to interface(s) |
| `(service id {:proto :tcp :port N\|[a b]})` | Named service (protocol + port(s)) |
| `(allow {...})` / `(deny {...})` / `(reject {...})` | Static rule between zones, optional `:service` |
| `(sandbox id {...})` | Declares limits for dynamic AI rules |

The **sandbox** is where AI power is defined:

- `:actions` — allowlist; currently `#{:drop-ip :rate-limit}` (closed set)
- `:default-ttl` / `:max-ttl` — every dynamic rule *must* expire
- `:max-active` — budget cap on simultaneously live dynamic rules

Compilation is deterministic: same policy in, byte-identical ruleset out.
Output includes timeout-backed nft sets per sandbox action
(`containment_drop`, `containment_rate-limit`).

## Using Vallum with models

This is the core of Vallum. The flow:

```
events (NDJSON) → manifest + events → LLM → proposals (data)
      → validator (spec + sandbox limits) → runtime (nftables + TTL + journal)
```

### 1. The data contracts

Three closed schemas (enforced by clojure.spec, unknown keys are rejected):

**Event** (what the operator's pipeline curates and feeds in):

```json
{"ts": "2026-08-22T20:14:59Z", "kind": "ssh.bruteforce",
 "src-ip": "203.0.113.7", "severity": 8, "refs": ["alert#4821"]}
```

Required: `ts`, `kind`, `src-ip`. Optional: `severity` (0–10), `refs`.

**Dynamic rule** (the ONLY thing a model may produce):

```json
{"action": "drop-ip", "ip": "203.0.113.7", "ttl": "30m",
 "reason": "SSH brute force", "source": "agent/gemini",
 "ts": "2026-08-22T20:15:30Z"}
```

All six keys required; `action` must be in the sandbox allowlist; `ttl`
parsed and capped at `max-ttl`; strings length-capped; extra keys rejected.

**Sandbox** — declared in the policy (above), enforced at validation time.

### 2. The manifest

The manifest is the model's *field of vision*: a JSON/EDN summary of what
the compiled policy permits. It is identical across backends.

```clojure
(require '[vallum.manifest :as m])
(def manifest (m/make-manifest ir))
(m/manifest->json manifest)  ; feed this to the LLM
```

### 3. The bridge protocol

Every provider implements two methods — that's the whole contract
(`vallum.bridge.protocol/LLMBridge`):

| Method | Input | Output |
|---|---|---|
| `build-context` | manifest + events | prompt string |
| `parse-proposal` | raw provider response | rule map(s) or `nil` |

A convenience function chains them around any send function:

```clojure
(bp/generate-proposals adapter manifest events send-fn)
;; = (parse-proposal adapter (send-fn (build-context adapter manifest events)))
```

### 4. Included adapters

**Stub (offline)** — deterministic, no network. Proposes `drop-ip` for
distinct source IPs of events meeting a severity threshold (default ≥ 7).
Ideal for tests, CI and demos:

```clojure
(require '[vallum.bridge.stub :as stub])
(def adapter (stub/make-stub-adapter manifest events))
;; options map: :min-severity threshold (default 7), :canned-proposals [...]
```

**Gemini (REST, zero dependencies)** — via `java.net.http`. Reads the key
from `VALLUM_GEMINI_KEY` (or pass it explicitly):

```bash
export VALLUM_GEMINI_KEY="your-api-key"
```

```clojure
(require '[vallum.bridge.gemini :as gemini]
         '[vallum.bridge.protocol :as bp])

(def g (gemini/make-gemini-adapter))              ; env var
;; (gemini/make-gemini-adapter "key")             ; explicit key
;; (gemini/make-gemini-adapter "key" "gemini-2.5-flash") ; custom model

(bp/generate-proposals g manifest events gemini/send-message)
```

The Gemini prompt template embeds the pretty-printed manifest and events,
then instructs the model to answer **only** with
`{"proposals": [...]}` — and to return an empty array when nothing warrants
containment.

### 5. Any other provider (Claude, GPT, Ollama, vLLM…)

Implement the two-method protocol, reusing Vallum's prompt structure. No
HTTP library needed — the JDK has one. Sketch for a local Ollama server:

```clojure
(defrecord OllamaAdapter [model url]
  bp/LLMBridge
  (build-context [_ manifest events]
    ;; reuse the same constraint style: manifest + events + JSON-only reply
    (format "...%s...%s..." (json/generate-string manifest)
            (json/generate-string events)))

  (parse-proposal [_ raw-response]
    ;; extract the message text from the provider's response shape,
    ;; parse the inner JSON, keywordize actions
    ...))

(bp/generate-proposals (->OllamaAdapter "llama3" "http://localhost:11434")
                       manifest events send-fn)
```

Because validation happens downstream in Vallum — not in the prompt — a
misbehaving provider degrades to "no action taken", never to a firewall
change.

### 6. End-to-end: event → containment → expiry

Full working flow (this is exactly what `demo/e2e.sh` automates):

```clojure
(require '[vallum.ingest :as ingest]
         '[vallum.compile :as compile]
         '[vallum.manifest :as m]
         '[vallum.validate :as v]
         '[vallum.runtime :as rt]
         '[vallum.bridge.protocol :as bp]
         '[vallum.bridge.gemini :as gemini])

;; Policy → IR → manifest
(def ir (compile/compile-forms
          (read-string (str "[" (slurp "examples/edge-host.lisp") "]"))))
(def sandbox (:containment (:sandboxes ir)))
(def manifest (m/make-manifest ir))

;; Events (NDJSON file curated by your alerting pipeline)
(def {:keys [events]} (ingest/read-events-file "/var/log/vallum/events.ndjson"))

;; Ask the model
(def g (gemini/make-gemini-adapter))
(def proposals (bp/generate-proposals g manifest events gemini/send-message))

;; Validate EVERY proposal against the sandbox — the security boundary
(def valid (remove #(v/validate-dynamic-rule % sandbox) proposals))

;; Apply through the runtime: budget check, TTL tracking, journal
(def state (rt/init-state))                    ; journal: /var/log/vallum/journal.jsonl
(def backend (rt/->LiveNftables))              ; real nftables backend (needs root)
(doseq [rule valid]
  (rt/add-dynamic-rule! state backend rule :containment sandbox))

;; Housekeeping: expire due rules, detect drift
(rt/expire-due-rules! state backend)
(rt/drift-check state backend)                 ; nil when live state == expected hash
```

Prompt-injection attempt? Rejected before it reaches nftables:

```clojure
(v/validate-dynamic-rule
  {:action :accept :ip "0.0.0.0/0" :ttl "24h"        ; ← model was tricked
   :reason "ignore previous instructions" :source "agent/gemini"
   :ts "..."}
  sandbox)
;; => {:error :invalid-dynamic-rule ...}  — :accept ∉ #{:drop-ip :rate-limit}
```

## Runtime semantics

| Concern | Mechanism |
|---|---|
| **TTL expiry** | Every rule carries `expires-at`; `expire-due-rules!` removes it from nft sets and state |
| **Budget (I3)** | `add-dynamic-rule!` refuses new rules when active ≥ `max-active` |
| **Drift detection** | SHA-256 of the last applied ruleset vs live `nft list ruleset`; `drift-check` reports divergence |
| **Audit trail** | Append-only JSONL journal (one line per add/remove/expiry), path configurable via `init-state` |
| **Testability** | Backend is an injected protocol (`NftablesBackend`); bind `rt/*clock*` to travel through time |

Journal entry example:

```json
{"event":"rule-added","rule-id":"5a7be6e8-…","sandbox-id":"containment",
 "action":"drop-ip","ip":"203.0.113.7","ttl":"30m","ttl-secs":1800,
 "ts":1787523809318,"expires-at":1787525609317}
```

## Demo

```bash
bash demo/e2e.sh
```

Runs the full cycle offline against the stub bridge: policy compilation →
simulated SSH brute-force NDJSON → stub proposal → validation → apply →
prompt-injection rejection → TTL expiry → drift check. Requires no root and
no nftables (uses an in-memory backend).

## Development

```bash
clojure -M:test                 # full test suite
clojure -M:harness all          # kondo + fmt + architecture + unit (CI gate)
clojure -M:harness fast         # pre-commit subset
clojure -M:kondo --lint src test
clojure -M:fmt check src test    # or `fix` to auto-format
```

The harness (`docs/HARNESS.md`) enforces four gates:

| Gate | What it checks |
|---|---|
| **kondo** | zero lint errors |
| **fmt** | cljfmt-clean |
| **architecture** | strict downward layer dependencies, purity rules, docstrings, phase consistency |
| **unit** | 121 tests / 500+ assertions incl. generative + adversarial suites |

Git hooks enforce [Conventional Commits](https://www.conventionalcommits.org):
`bin/install-git-hooks.sh`. Example: `feat(bridge): add Ollama adapter`.

## Security model

Invariants applied at the IR level hold for every backend and every caller:

- **I0 — closed schema**: dynamic rules validated against a fixed spec; unknown keys rejected
- **I1 — allowlisted actions**: only what the sandbox declares exists
- **I2 — bounded lifetime**: invalid/unparseable/oversized TTL ⇒ rejected
- **I3 — budget**: hard cap on concurrent dynamic rules per sandbox
- **Drift**: any out-of-band mutation of nftables is detectable
- **No evaluation**: model output is parsed as data, never executed
- **Fail-closed**: adapter/network/spec failures yield *no action*, not degraded action

## Status & roadmap

v1 scope (**complete**): M0 DSL+IR · M1 nftables emitter · M2 validator ·
M3 harness/architecture gates · M4 runtime (TTL/budget/journal/drift) +
event ingestion · M5 multi-provider AI bridge + E2E demo.

Frozen until further review: pf/Forti/Cisco backends, additional ingestion
modes (fail2ban action, journald, webhook).

See [`docs/PROPOSAL.md`](docs/PROPOSAL.md) for rationale and invariants,
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for module map and tiers,
[`docs/HARNESS.md`](docs/HARNESS.md) for the quality gate.
