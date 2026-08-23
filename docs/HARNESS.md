# Vallum — Quality harness

> Single verification suite for all source code: lint, formatting,
> security (Trivy), architecture conventions and tests. Executable from
> REPL, CLI or pre-commit with the same checks and the same results.
>
> Complements `ARCHITECTURE.md` (§4 rules this harness enforces,
> §6 testing strategy) and `PROPOSAL.md` §5 (invariants).

---

## 1. Principles

1. **Checks return data, they don't print.** Each check is a function
   that produces `{:id :status :summary :details}`. Reporting is a separate
   layer (`print-report!`). This way the REPL consumes results
   programmatically and the CLI formats them.
2. **Milestone gating.** The check registry declares from which milestone
   each one applies; the phase lives in `vallum.system/version`
   (`:phase :M0` today). What arrives in M2 today is reported as `⏭️ skip`,
   never as an error nor as silence.
3. **Graceful degradation.** If Trivy is not installed, the check skips with
   instructions instead of breaking the suite. Hard enforcement lives in CI.
4. **Single source of truth.** REPL, CLI, pre-commit and (future) CI run
   exactly the same registry: `vallum.harness/registry`.
5. **No magic binaries.** clj-kondo and cljfmt are versioned Maven
   dependencies in `deps.edn` — no global installation needed.

## 2. Usage

### REPL (daily flow)

```bash
clojure -M:repl        # rebel-readline + dev/user.clj preloaded
```

```clojure
(refresh)                       ; reload code (tools.namespace)
(h/run-fast!)                   ; lint + format + architecture + tests
(h/run-checks)                  ; raw data of all applicable checks
(h/run-one :lint/kondo)         ; a single check
(h/run-checks [:security])      ; subset by prefix (:security/trivy-*)
(run-tests)                     ; full suite via vallum.run-all
```

### CLI

```bash
clojure -M:harness all        # full suite applicable to the current phase
clojure -M:harness fast       # the same thing the pre-commit runs
clojure -M:harness security   # Trivy only
clojure -M:harness list       # registered checks and their milestones
clojure -M:test               # only the test suite (exit 0/1)
```

## 3. The checks

| ID | What it does | Tool | Milestone |
|---|---|---|---|
| `:lint/kondo` | Static analysis of src and test | clj-kondo (via deps.edn) | M0 |
| `:format/cljfmt` | Verifies canonical formatting | cljfmt (via deps.edn) | M0 |
| `:security/trivy-fs` | HIGH/CRITICAL vulnerabilities, misconfig and secrets | Trivy binary | M0 |
| `:security/trivy-config` | IaC misconfigurations (no DB needed) | Trivy binary | M0 |
| `:conventions/architecture` | Dependency, purity and docs rules (see §5) | own clojure.test | M0 |
| `:tests/unit` | Whole suite under `test/`, auto-discovered | vallum.run-all | M0 |
| `:tests/generative` | I0–I8 under arbitrary inputs (test.check) | test/vallum/generative/ | **M2** |
| `:tests/adversarial` | Attack suites against the sandbox | test/vallum/adversarial/ | **M2** |

The M2 suites don't need to touch the harness: creating files in
`test/vallum/generative/` or `test/vallum/adversarial/` gets them discovered
automatically (when `:phase` reaches `:M2` they go from `skip` to running).

## 4. Pre-commit — instant feedback

Two equivalent paths over the same source (`bin/hooks/`):

```bash
# A) Plain git, no Python nor dependencies (recommended):
./bin/install-git-hooks.sh

# B) Python's pre-commit, if you already have it:
pip install pre-commit && pre-commit install && pre-commit install --hook-type commit-msg
```

What each commit runs:
- **pre-commit:** `clojure -M:harness fast` → kondo + cljfmt + architecture
  + tests (~10 s). Failure ⇒ commit blocked with immediate feedback.
- **trivy.sh:** quick scan if the binary exists; if not, warns and continues.
  Install it with `./bin/install-trivy.sh` (lands in `~/.local/bin`, no sudo).
- **commit-msg:** Conventional Commits
  (`feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert[(scope)]!:`),
  consistent with the repo history.

To skip the hook once (conscious exceptions):
`git commit --no-verify`. The full suite runs again in CI.

## 5. Enforced conventions (test/vallum/architecture_test.clj)

Executable encoding of `ARCHITECTURE.md` §2/§4:

| Test | Rule |
|---|---|
| `namespaces-under-vallum-with-docstring` | Every ns lives in `vallum.*` and documents its responsibility |
| `domain-modules-registered-in-docs` | Every module appears in the §2 map and has a level in the graph |
| `downward-dependencies` | Only requires downward/sideways (§4); nobody touches the harness |
| `bridge-never-touches-runtime` | Bridges only emit EDN towards validate |
| `pure-layers-are-deterministic` | dsl/ir/compile/validate/emit/manifest/audit: no I/O, no time, no randomness (**I0/I4**) |
| `io-only-at-the-frontier` | I/O forbidden outside `{runtime, ingest, cli, harness}` (§4) |

**When adding a new module:** create `src/vallum/<module>/…` with docstring →
add it to `tiers` in `architecture_test.clj` → add it to table §2 of
`ARCHITECTURE.md`. The tests will demand all three steps.

## 6. Adding a check to the registry

1. Write the function in `vallum.harness`: no printing, returns
   `(result <id> ::pass|::fail|::skip "summary" "optional-details")`.
2. Register it in `registry` with its `:label` and `:milestone` (if any).
3. Done: REPL, CLI (`list`, `all`) and pre-commit inherit it.
4. Add a meta-test in `test/vallum/harness_test.clj` if it introduces new
   pure logic (selection, state semantics, etc.).

## 7. Harness status and roadmap

- [x] M0 — registry, milestone gating, kondo/cljfmt via deps.edn, Trivy with
      graceful degradation, architecture/conventions, unified runner,
      git hooks + pre-commit config.
- [ ] M2 — activate generative and adversarial suites (auto-discovered);
      CI job that runs `clojure -M:harness all` (+ native build, §7.1
      of PROPOSAL).
- [ ] M4+ — drift checks between declared policy and live-state fixtures
      when runtime and ingest exist.
