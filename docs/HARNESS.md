# Vallum — Harness de calidad

> Suite única de verificación para todo el source code: lint, formato,
> seguridad (Trivy), convenciones de arquitectura y tests. Ejecutable desde
> REPL, CLI o pre-commit con los mismos checks y los mismos resultados.
>
> Complementa a `ARCHITECTURE.md` (§4 reglas que este harness enforcea,
> §6 estrategia de pruebas) y a `PROPOSAL.md` §5 (invariantes).

---

## 1. Principios

1. **Los checks devuelven datos, no imprimen.** Cada check es una función
   que produce `{:id :status :summary :details}`. El reporteo es una capa
   aparte (`print-report!`). Así el REPL consume resultados programáticamente
   y el CLI los formatea.
2. **Gating por fase.** El registro de checks declara desde qué hito aplica
   cada uno; la fase vive en `vallum.system/version` (`:phase :M0` hoy).
   Lo que llega en M2 hoy se reporta como `⏭️ skip`, nunca como error ni
   como silencio.
3. **Degradación elegante.** Si Trivy no está instalado, el check salta con
   instrucciones en vez de romper la suite. La enforcement dura vive en CI.
4. **Una sola fuente de verdad.** REPL, CLI, pre-commit y (futuro) CI corren
   exactamente el mismo registro: `vallum.harness/registry`.
5. **Sin binarios mágicos.** clj-kondo y cljfmt son dependencias Maven
   versionadas en `deps.edn` — no hace falta instalar nada global.

## 2. Uso

### REPL (flujo diario)

```bash
clojure -M:repl        # rebel-readline + dev/user.clj precargado
```

```clojure
(refresh)                       ; recarga código (tools.namespace)
(h/run-fast!)                   ; lint + formato + arquitectura + tests
(h/run-checks)                  ; datos crudos de todos los checks aplicables
(h/run-one :lint/kondo)         ; un check puntual
(h/run-checks [:security])      ; subconjunto por prefijo (:security/trivy-*)
(run-tests)                     ; suite completa vía vallum.run-all
```

### CLI

```bash
clojure -M:harness all        # suite completa aplicable a la fase actual
clojure -M:harness fast       # lo mismo que corre el pre-commit
clojure -M:harness security   # solo Trivy
clojure -M:harness list       # checks registrados y sus hitos
clojure -M:test               # solo la suite de tests (exit 0/1)
```

## 3. Los checks

| ID | Qué hace | Herramienta | Hito |
|---|---|---|---|
| `:lint/kondo` | Análisis estático de src y test | clj-kondo (vía deps.edn) | M0 |
| `:format/cljfmt` | Verifica formato canónico | cljfmt (vía deps.edn) | M0 |
| `:security/trivy-fs` | Vulnerabilidades HIGH/CRITICAL, misconfig y secrets | Trivy binario | M0 |
| `:security/trivy-config` | Misconfigurations de IaC (no necesita DB) | Trivy binario | M0 |
| `:conventions/architecture` | Reglas de dependencia, pureza y docs (ver §5) | clojure.test propio | M0 |
| `:tests/unit` | Toda la suite bajo `test/` descubierta automáticamente | vallum.run-all | M0 |
| `:tests/generative` | I0–I8 bajo inputs arbitrarios (test.check) | test/vallum/generative/ | **M2** |
| `:tests/adversarial` | Suites de ataque al sandbox | test/vallum/adversarial/ | **M2** |

Las suites M2 no necesitan tocar el harness: al crear archivos en
`test/vallum/generative/` o `test/vallum/adversarial/` se descubren solos
(cuando `:phase` alcance `:M2` pasan de `skip` a ejecutarse).

## 4. Pre-commit — feedback instantáneo

Dos caminos equivalentes sobre la misma fuente (`bin/hooks/`):

```bash
# A) Git puro, sin Python ni dependencias (recomendado):
./bin/install-git-hooks.sh

# B) pre-commit de Python, si ya lo tenés:
pip install pre-commit && pre-commit install && pre-commit install --hook-type commit-msg
```

Qué corre cada commit:
- **pre-commit:** `clojure -M:harness fast` → kondo + cljfmt + arquitectura
  + tests (~10 s). Falla ⇒ commit bloqueado con feedback inmediato.
- **trivy.sh:** escaneo rápido si el binario existe; si no, avisa y continúa.
  Instalarlo con `./bin/install-trivy.sh` (queda en `~/.local/bin`, sin sudo).
- **commit-msg:** Conventional Commits
  (`feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert[(scope)]!:`),
  consistente con el historial del repo.

Para saltar el hook una vez (excepciones conscientes):
`git commit --no-verify`. La suite completa vuelve a correr en CI.

## 5. Convenciones enforceadas (test/vallum/architecture_test.clj)

Codificación ejecutable de `ARCHITECTURE.md` §2/§4:

| Test | Regla |
|---|---|
| `namespaces-bajo-vallum-con-docstring` | Todo ns vive en `vallum.*` y documenta su responsabilidad |
| `modulos-de-dominio-registrados-en-docs` | Todo módulo figura en el mapa §2 y tiene nivel en el grafo |
| `dependencias-descendentes` | Solo se requiere hacia abajo/lateral (§4); nadie toca al harness |
| `bridge-nunca-toca-runtime` | Los bridges solo emiten EDN hacia validate |
| `capas-puras-son-deterministas` | dsl/ir/compile/validate/emit/manifest/audit: sin I/O, sin tiempo, sin azar (**I0/I4**) |
| `io-solo-en-la-frontera` | I/O prohibida fuera de `{runtime, ingest, cli, harness}` (§4) |

**Al agregar un módulo nuevo:** crear `src/vallum/<modulo>/…` con docstring →
agregarlo a `tiers` en `architecture_test.clj` → agregarlo a la tabla §2 de
`ARCHITECTURE.md`. Los tests te van a exigir los tres pasos.

## 6. Agregar un check al registro

1. Escribir la función en `vallum.harness`: sin printing, devuelve
   `(result <id> ::pass|::fail|::skip "resumen" "detalles-opcionales")`.
2. Registrarla en `registry` con su `:label` y `:milestone` (si aplica).
3. Listo: REPL, CLI (`list`, `all`) y pre-commit la heredan.
4. Agregar meta-test en `test/vallum/harness_test.clj` si introduce lógica
   nueva pura (selección, semántica de estados, etc.).

## 7. Estado y roadmap del harness

- [x] M0 — registro, gating por fase, kondo/cljfmt vía deps.edn, Trivy con
      degradación elegante, arquitectura/convenciones, runner unificado,
      hooks git + pre-commit config.
- [ ] M2 — activar suites generativa y adversarial (auto-descubiertas);
      job de CI que corra `clojure -M:harness all` (+ build nativo, §7.1
      de PROPOSAL).
- [ ] M4+ — checks de drift entre política declarada y fixtures de estado
      vivo cuando existan runtime e ingest.
