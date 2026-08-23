# Vallum — Compilador de políticas de firewall con sandbox para agentes IA

> *Vallum* (latín): muralla, empalizada defensiva romana.

**Estado:** Propuesta v0.2 — pendiente de aprobación. Sin código todavía.

---

## 1. Pitch (2 líneas)

Un DSL en Clojure que compila políticas de firewall de alto nivel a reglas
verificables, y un formato de datos cerrado por el cual un agente IA
(**cualquier LLM**, vía puente multi-proveedor) puede **responder a
incidentes** sin poder jamás salirse del campo de acción definido por el
compilador.

**Objetivo primario:** Linux + nftables. **Evolución diseñada desde día 1:**
backends para pf (BSD) y, más adelante, plataformas API-centradas
(Fortinet, Cisco) mediante una representación intermedia neutra.

## 2. Problema

- Los LLM escriben nftables crudo de forma poco confiable y peligrosa.
- La respuesta automatizada a incidentes de red exige reglas dinámicas
  (bloqueos temporales, rate-limits), pero dar escritura arbitraria del
  firewall a software autónomo es inaceptable.
- Los rulesets crecen hasta volverse inauditables: reglas sombreadas,
  conflictos y drift entre la política declarada y el estado vivo.

## 3. Tesis central

**La IA nunca habla nftables. Habla datos.** El sistema separa dos mundos:

| Mundo | Quién escribe | Formato | Poder |
|---|---|---|---|
| **Política base** | Humanos (git) | S-expressions + macros Clojure | Total (compilado) |
| **Reglas dinámicas** | Agente IA u operador | **EDN puro, sin evaluación** | Solo acciones allowlisteadas, con TTL |

El agente produce *datos* contra un schema cerrado. Nunca invoca código,
nunca emite sintaxis nftables. El compilador —determinista— decide qué es
posible. Lo que el DSL no puede expresar, no existe.

## 4. Arquitectura

```
┌─────────────────────────────────────────────────────────┐
│ Capa 0 · Política (humanos, git)                        │
│   policy.lisp — zonas, servicios, macros                │
├─────────────────────────────────────────────────────────┤
│ Capa 1 · Compilador (Clojure, determinista)             │
│   macros → reglas nftables concretas                    │
├─────────────────────────────────────────────────────────┤
│ Capa 2 · Validador (clojure.spec + invariantes I0–I8)   │
│   rechaza por construcción lo peligroso                 │
├─────────────────────────────────────────────────────────┤
│ Capa 3 · IR — representación intermedia neutra          │
│   reglas como datos (EDN tipado por spec)               │
│   ★ las invariantes I0–I8 se aplican AQUÍ ⇒             │
│     valen para cualquier backend                        │
├───────────────────────┬─────────────────────────────────┤
│ Capa 4 · Backends     │                                 │
│  v1: ruleset.nft      │  manifest.json/.edn (para IA,   │
│  v1.5: pf (BSD)       │  idéntico en todos los backends)│
│  exp.: FortiOS, IOS   │                                 │
├───────────────────────┴─────────────────────────────────┤
│ Capa 5 · Runtime                                        │
│   aplica, vigila TTLs, detecta drift, audita            │
├─────────────────────────────────────────────────────────┤
│ Capa 6 · Puente IA — seguro, multi-proveedor            │
│   adaptadores: Gemini, Claude, GPT, Ollama, vLLM…       │
│   contexto = manifest → propone reglas EDN → Capa 2     │
└─────────────────────────────────────────────────────────┘
```

Flujo del agente: `alerta → IA propone EDN → validador (Capa 2) → dry-run →
apply → expira por TTL → registro de auditoría`. Toda decisión pasa
obligatoriamente por el mismo validador, venga de donde venga.

### Representación intermedia (IR) y backends

La IR es un conjunto de mapas EDN tipados por spec: zonas, servicios,
reglas de política y reglas dinámicas. Cada backend es una **función pura**
`IR → salida` (texto nft, config pf, llamadas REST…). El compilador emite IR;
los backends la consumen. Consecuencias directas:

- Las invariantes de seguridad se verifican una sola vez (sobre la IR) y
  heredan todos los backends.
- El manifiesto para la IA no cambia entre plataformas.
- Agregar un backend no toca el compilador ni el validador.

| Backend | Mecanismo dinámico | Encaje | Estado |
|---|---|---|---|
| **Linux nftables** | sets con `timeout` + namespace efímero | nativo — backend de referencia | **v1** |
| **OpenBSD/FreeBSD pf** | anchors + `<tables> persist` | muy bueno | v1.5 |
| **Cisco IOS/ASA** | ACLs numeradas vía SSH/NETCONF | bueno para contención (drop/rate-limit); TTL agendado por runtime | exploratorio |
| **Fortinet FortiOS** | objetos + políticas vía REST API | bueno para contención; TTL agendado por runtime | exploratorio |

Nota honesta: en nftables/pf el TTL lo resuelve la plataforma (timeouts de
sets / anchors descargados). En plataformas API-centradas (Cisco/Forti), el
runtime debe agendar la expiración vía API — misma semántica, mecánica distinta.

### Puente IA seguro (multi-proveedor)

El puente es la única puerta de entrada del LLM al sistema, y es
**agnóstico al proveedor**: un protocolo de adaptadores donde cada modelo
(Gemini, Claude, GPT, Ollama local, vLLM self-hosted…) implementa la misma
interfaz mínima:

```clojure
(defprotocol LLMBridge
  (contexto [this manifest eventos] "arma el prompt con estado + alertas")
  (proponer [this respuesta-cruda] "parsea la salida del modelo a EDN candidato"))
```

Propiedades de diseño:

- **El contrato vive en Vallum, no en el modelo.** El adaptador convierte la
  respuesta cruda a EDN y la entrega *siempre* al validador (Capa 2). Ningún
  adaptador tiene ruta directa a apply.
- **Modelo no confiable por diseño:** como la seguridad depende solo del
  compilador/validador, cambiar o mezclar proveedores no altera las
  garantías. Un modelo tonto produce reglas rechazadas; un modelo malicioso
  también.
- **Degradación elegante:** sin API disponible, un adaptador local (Ollama)
  u operador humano ocupan el mismo lugar. El runtime funciona igual.
- **Comparabilidad:** mismo manifiesto + mismos eventos ⇒ benchmark justo
  entre modelos sobre tasa de propuestas válidas/rechazadas.

### Boceto del DSL

Política humana (`policy.lisp`):

```clojure
(policy "edge-host"
  (zone wan {:iface "eth0"})
  (zone lan {:iface "eth1"})
  (service ssh {:proto :tcp :port 22})
  (service web {:proto :tcp :port [80 443]})

  (allow {:from :lan :to :wan})
  (allow {:from :wan :to :lan :service :web})

  ;; El único espacio donde la IA tiene voz:
  (sandbox containment
    {:actions      #{:drop-ip :rate-limit}
     :default-ttl  "30m"
     :max-ttl      "24h"
     :max-active   50}))
```

Regla dinámica producida por la IA (solo datos):

```clojure
{:action  :drop-ip
 :ip      "203.0.113.66"
 :ttl     "45m"
 :reason  "SSH brute-force: 200 intentos/min (alerta #4821)"
 :source  :agent/gemini
 :ts      "2026-08-22T20:15:00Z"}
```

Las marcas `:reason`, `:source`, `:ts` son obligatorias: toda regla lleva su
justificación legible y trazable.

## 5. Garantías de seguridad (invariantes del compilador)

Enforced por código, no por convención. Verificadas con tests generativos.

| ID | Invariante |
|----|------------|
| **I0** | Las reglas dinámicas son EDN puro. No existe ruta de evaluación de código proveniente de la IA. |
| **I1** | El vocabulario dinámico es cerrado: solo `drop-ip` y `rate-limit`. `accept`, `flush`, `delete`, manipulación de cadenas base: **no expresables**. |
| **I2** | Toda regla dinámica lleva TTL ≤ `max-ttl`. Expiración gestionada por el runtime; si el proceso muere, las reglas mueren con él (namespace efímero de nftables). |
| **I3** | Presupuesto de riesgo: máx. N reglas activas, máx. M IPs contenidas simultáneamente. Un agente desbocado se auto-limita. |
| **I4** | Determinismo: misma política + mismas reglas dinámicas ⇒ mismo ruleset byte a byte (hash auditable en cada apply). |
| **I5** | Dry-run por defecto. Apply exige flag explícito; modo `--approve-human` configurable para acciones de mayor impacto. |
| **I6** | Trazabilidad total: cada regla registra origen, razón, timestamp y hash del manifiesto vigente. |
| **I7** | El runtime opera con privilegios mínimos (`CAP_NET_ADMIN`, sin root pleno cuando sea posible). |
| **I8** | Neutralidad de proveedor: ningún componente de seguridad depende del LLM. Todo modelo es intercambiable porque se le trata como no confiable; su única salida posible es EDN candidato que pasa por el validador. |

**Prueba adversarial obligatoria (hito M2):** suite de ataques al sandbox —
prompt injection vía logs, EDN malicioso, lectura-antes-de-evaluar, abuso de
presupuesto. El sistema debe rechazarlos todos y dejar registro.

## 6. Alcance

**Dentro (v1):**
- Un host Linux con nftables (backend de referencia).
- DSL de política + compilador determinista + **IR neutra** + emisores
  nft/JSON.
- Runtime con TTLs, drift detection y auditoría.
- Puente IA multi-proveedor (protocolo de adaptadores) con adaptador Gemini
  incluido para generación de reglas dinámicas con validación completa.
- Demo end-to-end reproducible (script de ataque simulado incluido).

**Roadmap posterior a v1:**
- **v1.5:** backend pf (OpenBSD/FreeBSD) — mismo DSL, demo en BSD.
- **Exploratorio:** backends API-centrados FortiOS y Cisco IOS/ASA,
  restringidos a acciones de contención (`drop-ip`, `rate-limit`).

**Fuera (explícitamente):**
- Firewalls cloud (AWS SG, GCP FW), multi-host/orquestación → v2.
- Entrenamiento o hosting de modelos propios: solo consumo de API.
- Reemplazar firewalls empresariales: nicho homelab/small-biz/lab.

## 7. Stack

- **GraalVM como JDK del proyecto desde M0** (modo JIT para desarrollo);
  native-image compilado y testeado en CI desde M2. Ponderación completa en
  §7.1.
- `clojure.spec` — schemas e invariantes.
- `test.check` — **tests generativos**: políticas arbitrarias deben cumplir I0–I8 siempre.
- `cheshire` — JSON.
- CLI propia; adaptadores LLM vía HTTP REST puro (sin SDKs pesados), Gemini
  primero, Ollama como opción offline.
- Demo: VM/container Debian con nftables.

### 7.1 Ponderación JVM vs GraalVM native-image → decisión: GraalVM desde el inicio

El mismo código Clojure corre en ambos mundos. La distinción clave es que
GraalVM tiene **dos modos**: JIT (es un JDK más, desarrollo idéntico a JVM
estándar) y native-image/AOT (el modo restringido donde viven las
restricciones de reflexión). Eso permite una estrategia híbrida:

- **Desde M0:** GraalVM como JDK del proyecto (modo JIT) — experiencia de
  desarrollo idéntica a JVM estándar, cero costo diario.
- **Desde M2:** job de CI que compila native-image y corre la suite de tests
  sobre el binario. Los metadatos de reflexión (`reachability-metadata`,
  `clj-easy/graal-build-time`) se mantienen **incrementalmente** con cada
  dependencia, nunca como big-bang tardío.
- **Artefacto de distribución:** fat-jar por defecto hasta que un disparador
  objetivo pida publicar el binario nativo — que ya existirá, probado en CI.

Peso de las diferencias (para contexto de la decisión):

| Dimensión | JVM fat-jar | GraalVM native | Resolución con la estrategia híbrida |
|---|---|---|---|
| RAM en reposo (daemon) | 150–300 MB | 20–50 MB | Binario nativo disponible cuando haga falta |
| Distribución | Requiere JRE (~200 MB) | Binario único | Idem |
| Loop dev/build | Segundos | Minutos + config | Dev en modo JIT: costo nulo |
| Compatibilidad | Total | Casos borde (spec/Jackson) | Detectados en CI desde M2, no al final |

**Disparadores para publicar el binario nativo como artefacto principal:**
- distribución a terceros («binario único»), o
- deployment en hardware limitado (<1 GB RAM: routers, SBCs);
- alternativa intermedia si solo molesta el tamaño: **jlink** (~50 MB).

## 8. Hitos demostrables

| Hito | Entregable | Criterio de aceptación |
|------|-----------|------------------------|
| **M0** | Repo + estructura deps.edn | `clojure -M:dev` corre tests vacíos |
| **M1** | DSL core + compilador | Genera `ruleset.nft` válido; `nft -c` lo acepta |
| **M2** | Validador + invariantes I0–I8 | Suite adversarial pasa; tests generativos verdes; **build nativo verde en CI** |
| **M3** | Emisor manifest + auditoría semántica | Detecta reglas sombreadas en fixture conocido |
| **M4** | Runtime (apply, TTL, drift) | Regla dinámica expira sola; drift reportado ante cambio manual |
| **M5** | Puente IA (adaptador Gemini + stub offline) | Demo E2E: ataque simulado → contención automática → expiry |

Los hitos M0–M5 constituyen v1 (nftables). Post-v1:

| Hito | Entregable | Criterio de aceptación |
|------|-----------|------------------------|
| **M6** | Backend pf | La misma política compila a `pf.conf` con anchors; demo en OpenBSD/FreeBSD |
| **M7** | Backend API (FortiOS o IOS/ASA) | Contención aplicada y expirada vía API en laboratorio |

## 9. Escenario demo final («el momento dinero»)

1. Host demo: web pública + SSH.
2. Script simula brute-force SSH → alimenta alertas al runtime.
3. El adaptador Gemini propone `drop-ip` con TTL → validador aprueba → se
   aplica → expira.
4. **Ataque 2:** alerta envenenada con prompt injection que pide «abrir puerto
   22 a todo Internet» → el validador la rechaza porque *no es expresable* →
   queda registrada como intento violado.
5. `git diff` de la política vs estado vivo: cero drift no explicado.

## 10. Decisiones tomadas

- [x] Nombre: **Vallum**.
- [x] Clojure como lenguaje (vs Common Lisp).
- [x] Puente IA multi-proveedor con protocolo de adaptadores; Gemini primero,
      Ollama opcional offline.
- [x] Distribución: **GraalVM como JDK desde M0 (modo JIT)**, native-image
      verificado en CI desde M2, metadatos de reflexión incrementales;
      artefacto final según disparadores (§7.1).

## 11. Preguntas abiertas (decidir antes de M1)

- [ ] Mecanismo de ingesta de alertas v1: fail2ban, logs crudos o archivo de eventos propio.
- [ ] ¿Diseñar la IR ya con conceptos API-centrados en mente (objetos direccionados) o estrictamente nft-like en v1?
