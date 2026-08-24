# Vallum — High-level architecture

> Operational companion to `PROPOSAL.md`. Defines modules, dependencies,
> repo structure and testing strategy. v0.1 — refined during M1–M2.
>
> **Positioning** (adjusted by external review): *constrained policy
> compiler and runtime for autonomous network remediation*. The AI is just
> another consumer of the dynamic interface, not the product.

---

## 1. Structural principle

**Strictly downward dependencies**: each layer only knows lower layers.
Nothing depends on the runtime. The validator depends solely on the IR —
so invariants are verifiable without compiling or touching the system.

```
        high layer                                low layer
dsl ──▶ compiler ──▶ ir ◀──── validator          (pure, no I/O)
                        │  ▲
              emit/nft ─┘  └── manifest            (pure functions)

ingest ──▶ validated events ────┐
bridge ──▶ candidate EDN ───────┼──▶ validator ──▶ runtime (only one with I/O)
human CLI ──────────────────────┘
```

## 2. Module map (`src/vallum/`)

| Namespace | Responsibility | Depends on | Milestone |
|---|---|---|---|
| `dsl` | Policy macros: `policy`, `zone`, `service`, `allow`, `sandbox` | — (expands to data) | M1 |
| `ir` | Versioned IR schema + extensible type registry | — | M1 |
| `compile` | Policy → IR (determinism I4 lives here) | `dsl`, `ir` | M1 |
| `validate` | clojure.spec + invariants I0–I8 over IR and dynamic rules | `ir` | M2 |
| `emit.nft` | IR + active dynamics → `ruleset.nft` | `ir` | M1 |
| `manifest` | IR + dynamics → JSON/EDN for AI and audit | `ir` | M3 |
| `audit` | Shadow/conflict detection over the manifest | `manifest`, `ir` | M3 |
| `ingest` | Watches NDJSON file, validates event contract | `validate` (events) | M4 |
| `runtime` | Apply, TTL scheduler, drift, budget I3, journal | everything above | M4 |
| `bridge.protocol` | `LLMBridge`: adapter contract | `validate` | M5 |
| `bridge.gemini`, `bridge.stub` | Concrete/offline adapters | `bridge.protocol` | M5 |
| `cli` | Subcommands: `compile`, `validate`, `apply`, `audit`, `daemon` | `runtime` | transversal |

## 3. The two data paths

**Static path (humans):**
```
policy.lisp → dsl/macros → compiler → IR → [emit.nft | manifest]
```

**Dynamic path (agents/operator):**
```
NDJSON event → bridge (LLM) → candidate EDN ┐
human CLI ──────────────────────────────────┴→ validate (I0–I8) → runtime
                                                                      ├─ apply (nft)
                                                                      ├─ TTL scheduler
                                                                      ├─ drift check
                                                                      └─ audit JSONL
```

The two security boundaries (review: "much more robust"):
1. **Agent input:** only events from the curated channel — never raw logs.
2. **Agent output:** only EDN against a closed schema — never code,
   never nftables syntax.

## 4. Dependency rules (enforced by review + architecture test)

- `ir` and `validate` have no I/O nor infrastructure dependencies.
- Emitters are pure functions: same input ⇒ identical bytes (I4).
- Only `runtime` talks to nftables, state files and network.
- `bridge.*` never calls `runtime.apply` directly: its only output is EDN
  towards `validate`.

## 5. Repository structure

Code lives in `src/`; the rest of the repo hosts artifacts, CI and tooling:

```
Vallum/
├── docs/                    # proposal, architecture, harness, future ADRs
├── src/vallum/              # source code (§2 map)
├── test/vallum/             # unit tests + architecture/conventions tests
│   ├── generative/          # test.check: invariants under arbitrary inputs
│   └── adversarial/         # attack suite against the sandbox (see §6)
├── dev/                     # user.clj: REPL utilities
├── bin/                     # install-trivy.sh, install-git-hooks.sh, hooks/
├── examples/                # sample .lisp policies and IR fixtures
├── demo/                    # E2E scenario: attack script, VM/container
├── .github/workflows/       # CI: JIT matrix + native-image job (from M2)
├── .pre-commit-config.yaml  # harness fast (kondo/cljfmt/tests) + trivy + commit convention
├── deps.edn                 # aliases: :repl :test :kondo :fmt :harness :native
└── README.md                # when there is something worth documenting
```

## 6. Testing strategy (4 layers)

| Layer | Tool | What it tests | Milestone |
|---|---|---|---|
| Unit | `clojure.test` | expected behavior of each module | M0+ |
| Generative | `test.check` | I0–I8 hold for **arbitrary** policies/rules | M2 |
| Adversarial | fixed hostile fixtures | explicit, audited rejection of attacks | M2 |
| E2E | demo/ + VM container | full flow attack→containment→expiry | M5 |

Orchestration of all layers lives in the **harness** (`vallum.harness`,
documentation in `docs/HARNESS.md`): a single check registry with milestone
gating, executable from REPL, CLI and pre-commit. The dependency rules of §4
are enforced as tests in `test/vallum/architecture_test.clj`.

**Minimal adversarial suite (M2)** — attack classes, all must end in
rejection + audit record:
unknown keys · unknown actions · malformed EDN · unexpected nesting · type
confusion · giant integers · negative or zero TTL · NaN/weird numeric values ·
duplicate fields · hostile unicode · oversized strings · unexpected EDN tags ·
attempted `:open-port` / `:accept` / `:flush` (unexpressible by definition).

Gold criterion: the prompt injection "open port 22 to the Internet" fails
**because `:open-port` does not exist in the language**, not because a filter
detects it.

## 7. Milestones ↔ modules

| Milestone | Delivered modules | Criterion (summary of PROPOSAL §8) |
|---|---|---|
| M0 | scaffold, empty cli, JIT CI, pre-commit | green tests in CI |
| M1 | `dsl`, `ir`, `compile`, `emit.nft` | `nft -c` accepts the output |
| M2 | `validate` + generative/adversarial layers + native CI | suites green |
| M3 | `manifest`, `audit` | shadows detected in fixture |
| M4 | `ingest`, `runtime` | TTL expires; drift reported |
| M5 | `bridge.*`, E2E demo | full money moment |
| M6 | `runtime` (load-state), `cli` (ops subcommands) | journal replay across processes; `vallum apply/expire/drift/status` work standalone |
| M7 | agent SDK repo (Python/Go) | agent consumes native binary via JSON CLI |

Scope discipline (review): **M0–M5 and absolutely nothing more.** No pf,
no Forti/Cisco, no webhooks, no journald before M5.

## 8. Deferred internal decisions (resolved within M1–M2)

They do not block the start; recorded here so we don't improvise them:
- Internal representation of IR rules: flat maps vs records.
- Runtime journal format for recovery after restart.
- TTL scheduling: periodic sweep vs individual timers.
- Location of the audit log (default: `/var/lib/vallum/audit.jsonl`,
  configurable).
