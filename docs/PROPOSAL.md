# Vallum — Firewall policy compiler with a sandbox for AI agents

> *Vallum* (Latin): wall, Roman defensive palisade.

**Status:** Proposal v0.3 — approved after external review. Architecture
planning in `ARCHITECTURE.md`. No code yet.

**Scope discipline:** v1 = M0–M5 and nothing more. The pf/Forti/Cisco backends
and additional ingestion modes stay frozen until M5 is complete. M6 reorients
to native binary CLI; M7 to the external agent SDK (Python/Go).

---

## 1. Pitch (2 lines)

A Clojure DSL that compiles high-level firewall policies into **validated,
reproducible rules**, and a closed data format through which an AI agent
(**any LLM**, via a multi-provider bridge) can **respond to incidents**
without ever being able to step outside the field of action defined by the
compiler.

**Primary target:** Linux + nftables. **Evolution designed from day 1:**
backends for pf (BSD) and later API-centric platforms (Fortinet, Cisco)
through a neutral intermediate representation.

## 2. Problem

- LLMs write raw nftables unreliably and dangerously.
- Automated network incident response requires dynamic rules (temporary
  blocks, rate-limits), but giving arbitrary firewall write access to
  autonomous software is unacceptable.
- Rulesets grow until they become unauditable: shadowed rules, conflicts,
  and drift between the declared policy and the live state.

## 3. Central thesis

**The AI never speaks nftables. It speaks data.** The system separates two
worlds:

| World | Who writes it | Format | Power |
|---|---|---|---|
| **Base policy** | Humans (git) | S-expressions + Clojure macros | Full (compiled) |
| **Dynamic rules** | AI agent or operator | **Pure EDN, no evaluation** | Allowlisted actions only, with TTL |

The agent produces *data* against a closed schema. It never invokes code,
never emits nftables syntax. The compiler — deterministic — decides what is
possible. What the DSL cannot express does not exist.

## 4. Architecture

```
┌─────────────────────────────────────────────────────────┐
│ Layer 0 · Policy (humans, git)                          │
│   policy.lisp — zones, services, macros                 │
├─────────────────────────────────────────────────────────┤
│ Layer 1 · Compiler (Clojure, deterministic)             │
│   macros → concrete nftables rules                      │
├─────────────────────────────────────────────────────────┤
│ Layer 2 · Validator (clojure.spec + invariants I0–I8)   │
│   rejects the dangerous by construction                 │
├─────────────────────────────────────────────────────────┤
│ Layer 3 · IR — neutral intermediate representation      │
│   rules as data (EDN typed by spec)                     │
│   ★ invariants I0–I8 are applied HERE ⇒                 │
│     they hold for any backend                           │
├───────────────────────┬─────────────────────────────────┤
│ Layer 4 · Backends    │                                 │
│  v1: ruleset.nft      │  manifest.json/.edn (for AI,    │
│  v1.5: pf (BSD)       │  identical across backends)     │
│  exp.: FortiOS, IOS   │                                 │
├───────────────────────┴─────────────────────────────────┤
│ Layer 5 · Runtime                                       │
│   applies, watches TTLs, detects drift, audits          │
├─────────────────────────────────────────────────────────┤
│ Layer 6 · AI bridge — secure, multi-provider            │
│   adapters: Gemini, Claude, GPT, Ollama, vLLM…          │
│   context = manifest → proposes EDN rules → Layer 2     │
└─────────────────────────────────────────────────────────┘
```

Agent flow: `alert → AI proposes EDN → validator (Layer 2) → dry-run →
apply → expires by TTL → audit log`. Every decision must pass through the
same validator, no matter where it comes from.

### Intermediate representation (IR) and backends

The IR is a set of EDN maps typed by spec: zones, services, policy rules and
dynamic rules. Each backend is a **pure function** `IR → output` (nft text,
pf config, REST calls…). The compiler emits IR; backends consume it. Direct
consequences:

- Security invariants are verified once (over the IR) and inherited by all
  backends.
- The manifest for the AI does not change between platforms.
- Adding a backend does not touch the compiler or the validator.

**Design principle: minimal IR with an explicit growth path.**

- **v1 = the basics:** inline addresses/ports, zones, services, allow/deny,
  containment. Nothing else. Nothing premature.
- **Versioned schema:** every manifest carries `:ir/version`; schemas are
  closed (unknown keys ⇒ rejection) and evolve only through explicit
  versions.
- **Extensible object type registry:** new concepts (`:ir/named-object`,
  `:ir/service-group`, …) are registered without touching the compiler core
  or the validator.
- **Admission rule:** a concept enters the IR when (a) two backends know how
  to express it, or (b) nftables demands it. If only one future backend
  needs it, it waits in that backend's roadmap.
- **Concrete path:** when the API-centric backend arrives (M7, FortiOS/
  Cisco) which demands addressed objects, `:ir/named-object` gets registered
  and the compiler automatically derives objects from existing inline
  addresses — old policies keep compiling unchanged.

| Backend | Dynamic mechanism | Fit | Status |
|---|---|---|---|
| **Linux nftables** | sets with `timeout` + ephemeral namespace | native — reference backend | **v1** |
| **OpenBSD/FreeBSD pf** | anchors + `<tables> persist` | very good | v1.5 |
| **Cisco IOS/ASA** | numbered ACLs via SSH/NETCONF | good for containment (drop/rate-limit); TTL scheduled by runtime | exploratory |
| **Fortinet FortiOS** | objects + policies via REST API | good for containment; TTL scheduled by runtime | exploratory |

Honest note: in nftables/pf the TTL is solved by the platform (set timeouts /
unloaded anchors). On API-centric platforms (Cisco/Forti), the runtime must
schedule expiration via API — same semantics, different mechanics.

### Secure AI bridge (multi-provider)

The bridge is the single entry point of the LLM into the system, and it is
**provider agnostic**: an adapter protocol where each model (Gemini, Claude,
GPT, local Ollama, self-hosted vLLM…) implements the same minimal interface:

```clojure
(defprotocol LLMBridge
  (contexto [this manifest eventos] "builds the prompt with state + alerts")
  (proponer [this respuesta-cruda] "parses the model's output into candidate EDN"))
```

Design properties:

- **The contract lives in Vallum, not in the model.** The adapter converts
  the raw response to EDN and hands it *always* to the validator (Layer 2).
  No adapter has a direct path to apply.
- **Untrusted model by design:** since security depends only on the
  compiler/validator, switching or mixing providers does not alter the
  guarantees. A dumb model produces rejected rules; a malicious one too.
- **Graceful degradation:** with no API available, a local adapter (Ollama)
  or a human operator take the same place. The runtime works the same.
- **Comparability:** same manifest + same events ⇒ fair benchmark between
  models over valid/rejected proposal rates.

### Alert ingestion (v1: a single mode)

**v1 supports a single mode:** its own NDJSON event file (one line = one
event), watched by the runtime.

```json
{"ts":"2026-08-22T20:14:59Z","kind":"ssh.bruteforce","src_ip":"203.0.113.66","severity":7,"refs":["alerta#4821"]}
```

Properties:

- Closed schema validated at ingestion; malformed lines get rejected and
  logged, never crash the process.
- **Vallum does not read raw logs.** It consumes a channel curated by the
  operator: whoever deploys decides which events exist and can impose greater
  restrictions *externally* for compliance (upstream filtering/aggregation,
  controlled enrichment) and *internally* via sandbox budgets in their
  `policy.lisp`. The event contract is auditable on its own.
- Future modes (fail2ban action, journald, HTTP webhook) enter as adapters of
  the same pattern as the AI bridge: fixed contract, interchangeable source.
  Out of scope for v1.

### DSL sketch

Human policy (`policy.lisp`):

```clojure
(policy "edge-host"
  (zone wan {:iface "eth0"})
  (zone lan {:iface "eth1"})
  (service ssh {:proto :tcp :port 22})
  (service web {:proto :tcp :port [80 443]})

  (allow {:from :lan :to :wan})
  (allow {:from :wan :to :lan :service :web})

  ;; The only space where the AI has a voice:
  (sandbox containment
    {:actions      #{:drop-ip :rate-limit}
     :default-ttl  "30m"
     :max-ttl      "24h"
     :max-active   50}))
```

Dynamic rule produced by the AI (data only):

```clojure
{:action  :drop-ip
 :ip      "203.0.113.66"
 :ttl     "45m"
 :reason  "SSH brute-force: 200 attempts/min (alert #4821)"
 :source  :agent/gemini
 :ts      "2026-08-22T20:15:00Z"}
```

The `:reason`, `:source`, `:ts` marks are mandatory: every rule carries its
readable, traceable justification.

## 5. Security guarantees (compiler invariants)

Enforced by code, not by convention. Verified with generative tests.

| ID | Invariant |
|----|------------|
| **I0** | Dynamic rules are pure EDN. There is no code-evaluation path coming from the AI. |
| **I1** | The dynamic vocabulary is closed: only `drop-ip` and `rate-limit`. `accept`, `flush`, `delete`, base-chain manipulation: **not expressible**. |
| **I2** | Every dynamic rule carries TTL ≤ `max-ttl`. Expiration managed by the runtime; if the process dies, the rules die with it (ephemeral nftables namespace). |
| **I3** | Risk budget: max N active rules, max M contained IPs simultaneously. A runaway agent self-limits. |
| **I4** | Determinism: same policy + same dynamic rules ⇒ same ruleset byte for byte (auditable hash on every apply). |
| **I5** | Dry-run by default. Apply requires an explicit flag; configurable `--approve-human` mode for higher-impact actions. |
| **I6** | Full traceability: every rule records origin, reason, timestamp and hash of the current manifest. |
| **I7** | The runtime operates with least privilege (`CAP_NET_ADMIN`, no full root whenever possible). |
| **I8** | Provider neutrality: no security component depends on the LLM. Every model is interchangeable because it is treated as untrusted; its only possible output is candidate EDN that goes through the validator. |

**Mandatory adversarial test (milestone M2):** attack suite against the
sandbox — unknown keys/actions, malformed EDN, unexpected nesting, type
confusion, giant integers, negative TTL, NaN, duplicate fields, hostile
unicode, oversized strings, unexpected tags, prompt injection via logs. The
system must reject them all and leave a record. The criterion: "open port 22
to the Internet" fails because `:open-port` **does not exist in the
language**, not because a filter detects it.

## 6. Scope

**Inside (v1):**
- One Linux host with nftables (reference backend).
- Policy DSL + deterministic compiler + **neutral IR** + nft/JSON emitters.
- Runtime with TTLs, drift detection and auditing.
- Multi-provider AI bridge (adapter protocol) with a Gemini adapter included
  for dynamic rule generation with full validation.
- Reproducible end-to-end demo (attack simulation script included).

**Post-v1 roadmap:**
- **v1.5:** pf backend (OpenBSD/FreeBSD) — same DSL, demo on BSD.
- **Exploratory:** API-centric FortiOS and Cisco IOS/ASA backends, restricted
  to containment actions (`drop-ip`, `rate-limit`).

**Out (explicitly):**
- Cloud firewalls (AWS SG, GCP FW), multi-host/orchestration → v2.
- Training or hosting our own models: API consumption only.
- Replacing enterprise firewalls: homelab/small-biz/lab niche.

## 7. Stack

- **GraalVM as the project JDK from M0** (JIT mode for development);
  native-image compiled and tested in CI from M2. Full rationale in §7.1.
- `clojure.spec` — schemas and invariants.
- `test.check` — **generative tests**: arbitrary policies must always satisfy I0–I8.
- `cheshire` — JSON.
- Own CLI; LLM adapters via plain HTTP REST (no heavy SDKs), Gemini first,
  Ollama as offline option.
- Demo: Debian VM/container with nftables.

### 7.1 JVM vs GraalVM native-image weighing → decision: GraalVM from the start

The same Clojure code runs in both worlds. The key distinction is that
GraalVM has **two modes**: JIT (it is just another JDK, development identical
to standard JVM) and native-image/AOT (the restricted mode where reflection
constraints live). This allows a hybrid strategy:

- **From M0:** GraalVM as the project JDK (JIT mode) — developer experience
  identical to standard JVM, zero daily cost.
- **From M2:** CI job compiling native-image and running the test suite on
  the binary. Reflection metadata (`reachability-metadata`,
  `clj-easy/graal-build-time`) maintained **incrementally** with each
  dependency, never as a late big-bang.
- **Distribution artifact:** fat-jar by default until an objective trigger
  asks to publish the native binary — which will already exist, tested in CI.

Weight of the differences (for context of the decision):

| Dimension | JVM fat-jar | GraalVM native | Resolution with the hybrid strategy |
|---|---|---|---|
| Idle RAM (daemon) | 150–300 MB | 20–50 MB | Native binary available when needed |
| Distribution | Requires JRE (~200 MB) | Single binary | Same |
| Dev/build loop | Seconds | Minutes + config | Dev in JIT mode: zero cost |
| Compatibility | Total | Edge cases (spec/Jackson) | Detected in CI from M2, not at the end |

**Triggers to publish the native binary as the main artifact:**
- distribution to third parties ("single binary"), or
- deployment on limited hardware (<1 GB RAM: routers, SBCs);
- middle-ground alternative if only size bothers: **jlink** (~50 MB).

## 8. Demonstrable milestones

| Milestone | Deliverable | Acceptance criteria |
|------|-----------|------------------------|
| **M0** | Repo + deps.edn structure | `clojure -M:dev` runs empty tests |
| **M1** | DSL core + compiler | Generates valid `ruleset.nft`; accepted by `nft -c` |
| **M2** | Validator + invariants I0–I8 | Adversarial suite passes; generative tests green; **native build green in CI** |
| **M3** | Manifest emitter + semantic audit | Detects shadowed rules in known fixture |
| **M4** | Runtime (apply, TTL, drift) | Dynamic rule expires alone; drift reported upon manual change |
| **M5** | AI bridge (Gemini adapter + offline stub) | E2E demo: simulated attack → automatic containment → expiry |

Milestones M0–M5 constitute v1 (nftables). Post-v1:

| Milestone | Deliverable | Acceptance criteria |
|------|-----------|------------------------|
| **M6** | Native binary CLI | `load-state` replays journal across processes; `vallum apply|expire|drift|status` work as standalone invocations; GraalVM native-image builds in CI |
| **M7** | Agent SDK (Python/Go) | Agent repo consumes the native binary; `validate|propose|apply` orchestrated from external process with JSON I/O |

## 9. Final demo scenario ("the money moment")

1. Demo host: public web + SSH.
2. Script simulates SSH brute-force → writes NDJSON events to the ingestion
   file.
3. The Gemini adapter proposes `drop-ip` with TTL → validator approves →
   applied → expires.
4. **Attack 2:** poisoned alert with prompt injection asking to "open port 22
   to the whole Internet" → the validator rejects it because *it is not
   expressible* → recorded as a violated attempt.
5. `git diff` of the policy vs live state: zero unexplained drift.

## 10. Decisions made

- [x] Name: **Vallum**.
- [x] Clojure as language (vs Common Lisp).
- [x] Multi-provider AI bridge with adapter protocol; Gemini first, Ollama
      optional offline.
- [x] Distribution: **GraalVM as JDK from M0 (JIT mode)**, native-image
      verified in CI from M2, incremental reflection metadata; final artifact
      per triggers (§7.1).
- [x] v1 alert ingestion: **own NDJSON file**, channel curated by the
      operator (compliance-friendly); other future modes as adapters.
- [x] IR: **minimal in v1** (nft-like, inline addresses) with versioned
      schema and extensible type registry; growth by explicit admission rule
      (§4).

## 11. Open questions

None. The proposal is ready to start M0.
