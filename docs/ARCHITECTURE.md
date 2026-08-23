# Vallum — Arquitectura de alto nivel

> Complemento operativo de `PROPOSAL.md`. Define módulos, dependencias,
> estructura del repo y estrategia de pruebas. v0.1 — se refina durante M1–M2.
>
> **Posicionamiento** (ajustado por review externo): *constrained policy
> compiler and runtime for autonomous network remediation*. La IA es un
> consumidor más de la interfaz dinámica, no el producto.

---

## 1. Principio estructural

Dependencias **estrictamente descendentes**: cada capa solo conoce capas
inferiores. Nada depende del runtime. El validador depende únicamente de la
IR — así las invariantes son verificables sin compilar ni tocar el sistema.

```
        capa alta                                capa baja
dsl ──▶ compiler ──▶ ir ◀──── validator          (pura, sin I/O)
                        │  ▲
              emit/nft ─┘  └── manifest            (funciones puras)
                        
ingest ──▶ eventos validados ──┐
bridge ──▶ candidatos EDN ──────┼──▶ validator ──▶ runtime (único con I/O)
human CLI ─────────────────────┘
```

## 2. Mapa de módulos (`src/vallum/`)

| Namespace | Responsabilidad | Depende de | Hito |
|---|---|---|---|
| `dsl` | Macros de política: `policy`, `zone`, `service`, `allow`, `sandbox` | — (expande a datos) | M1 |
| `ir` | Schema versionado de la IR + registry extensible de tipos | — | M1 |
| `compile` | Política → IR (determinismo I4 vive aquí) | `dsl`, `ir` | M1 |
| `validate` | clojure.spec + invariantes I0–I8 sobre IR y reglas dinámicas | `ir` | M2 |
| `emit.nft` | IR + dinámicas vigentes → `ruleset.nft` | `ir` | M1 |
| `manifest` | IR + dinámicas → JSON/EDN para IA y auditoría | `ir` | M3 |
| `audit` | Detección de sombras/conflictos sobre manifiesto | `manifest`, `ir` | M3 |
| `ingest` | Vigila archivo NDJSON, valida contrato de eventos | `validate` (eventos) | M4 |
| `runtime` | Apply, scheduler de TTL, drift, presupuesto I3, journal | todo lo anterior | M4 |
| `bridge.protocol` | `LLMBridge`: contrato de adaptadores | `validate` | M5 |
| `bridge.gemini`, `bridge.stub` | Adaptadores concreto/offline | `bridge.protocol` | M5 |
| `cli` | Subcomandos: `compile`, `validate`, `apply`, `audit`, `daemon` | `runtime` | transversal |

## 3. Los dos caminos de datos

**Camino estático (humanos):**
```
policy.lisp → dsl/macros → compiler → IR → [emit.nft | manifest]
```

**Camino dinámico (agentes/u operador):**
```
evento NDJSON → bridge (LLM) → candidato EDN ┐
human CLI ────────────────────────────────────┴→ validate (I0–I8) → runtime
                                                                      ├─ apply (nft)
                                                                      ├─ TTL scheduler
                                                                      ├─ drift check
                                                                      └─ audit JSONL
```

Las dos fronteras de seguridad (review: «mucho más robusto»):
1. **Entrada al agente:** solo eventos del canal curado — nunca logs crudos.
2. **Salida del agente:** solo EDN contra schema cerrado — nunca código,
   nunca sintaxis nftables.

## 4. Reglas de dependencia (enforced por revisión + test de arquitectura)

- `ir` y `validate` no tienen I/O ni dependencias de infraestructura.
- Los emisores son funciones puras: mismo input ⇒ bytes idénticos (I4).
- Solo `runtime` habla con nftables, archivos de estado y red.
- `bridge.*` jamás llama a `runtime.apply` directo: su única salida es EDN
  hacia `validate`.

## 5. Estructura del repositorio

El código vive en `src/`; el resto del repo aloja artefactos, CI y tooling:

```
Vallum/
├── docs/                    # propuesta, arquitectura, harness, ADRs futuros
├── src/vallum/              # código fuente (mapa §2)
├── test/vallum/             # tests unitarios + arquitectura/convenciones
│   ├── generative/          # test.check: invariantes bajo inputs arbitrarios
│   └── adversarial/         # suite de ataques al sandbox (ver §6)
├── dev/                     # user.clj: utilidades de REPL
├── bin/                     # install-trivy.sh, install-git-hooks.sh, hooks/
├── examples/                # políticas .lisp de ejemplo y fixtures de IR
├── demo/                    # escenario E2E: script de ataque, VM/container
├── .github/workflows/       # CI: JIT matrix + job native-image (desde M2)
├── .pre-commit-config.yaml  # harness fast (kondo/cljfmt/tests) + trivy + convención de commits
├── deps.edn                 # aliases: :repl :test :kondo :fmt :harness :native
└── README.md                # cuando exista algo que documentar
```

## 6. Estrategia de pruebas (4 capas)

| Capa | Herramienta | Qué prueba | Hito |
|---|---|---|---|
| Unitaria | `clojure.test` | comportamiento esperado de cada módulo | M0+ |
| Generativa | `test.check` | I0–I8 se cumplen para políticas/reglas **arbitrarias** | M2 |
| Adversarial | fixtures hostiles fijos | rechazo explícito y auditado de ataques | M2 |
| E2E | demo/ + VM container | flujo completo ataque→contención→expiry | M5 |

La orquestación de todas las capas vive en el **harness** (`vallum.harness`,
documentación en `docs/HARNESS.md`): registro único de checks con gating por
hito, ejecutable desde REPL, CLI y pre-commit. Las reglas de dependencia de
§4 están enforceadas como tests en `test/vallum/architecture_test.clj`.

**Suite adversarial mínima (M2)** — clases de ataque, todas deben terminar en
rechazo + registro de auditoría:
claves desconocidas · acciones desconocidas · EDN malformado · anidamiento
inesperado · confusión de tipos · enteros gigantes · TTL negativo o cero ·
NaN/valores numéricos raros · campos duplicados · unicode hostil · strings
sobredimensionados · tags EDN inesperados · intento de `:open-port` /
`:accept` / `:flush` (inexpresable por definición).

Criterio de oro: el prompt injection «abrí el puerto 22 a Internet» falla
**porque `:open-port` no existe en el lenguaje**, no porque un filtro lo
detecte.

## 7. Hitos ↔ módulos

| Hito | Módulos entregados | Criterio (resumen de PROPOSAL §8) |
|---|---|---|
| M0 | scaffold, cli vacío, CI JIT, pre-commit | tests verdes en CI |
| M1 | `dsl`, `ir`, `compile`, `emit.nft` | `nft -c` acepta el output |
| M2 | `validate` + capas generativa/adversarial + CI nativo | suites verdes |
| M3 | `manifest`, `audit` | sombras detectadas en fixture |
| M4 | `ingest`, `runtime` | TTL expira; drift reportado |
| M5 | `bridge.*`, demo E2E | momento dinero completo |

Disciplina de alcance (review): **M0–M5 y absolutamente nada más.** Ni pf,
ni Forti/Cisco, ni webhooks, ni journald antes de M5.

## 8. Decisiones internas diferidas (se resuelven dentro de M1–M2)

No bloquean el arranque; quedan registradas para no improvisarlas:
- Representación interna de reglas IR: maps planos vs records.
- Formato del journal del runtime para recuperación tras restart.
- Scheduling de TTL: sweep periódico vs timers individuales.
- Ubicación del audit log (default: `/var/lib/vallum/audit.jsonl`,
  configurable).
