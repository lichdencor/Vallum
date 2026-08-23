(ns vallum.harness
  "Suite de calidad de Vallum: lint, formato, seguridad (Trivy), convenciones
  de arquitectura y tests — ejecutable desde REPL o CLI.

  Filosofía:
  - Cada check es una función pura-ish que DEVUELVE DATOS (nunca imprime).
    El reporteo es una capa aparte, así el REPL consume resultados y el CLI
    los formatea.
  - Los checks se activan por hito (:phase en vallum.system): lo que llega
    en M2 (tests generativos/adversariales) hoy se reporta como :skip.
  - Degradación elegante: si Trivy no está instalado, el check salta con
    instrucciones en vez de romper la suite.

  Uso en REPL:
    (require '[vallum.harness :as h])
    (h/run-checks)                    ; suite completa aplicable a esta fase
    (h/report (h/run-checks))         ; con salida legible
    (h/run-checks [:lint])            ; subconjunto por prefijo de id
    (h/run-one :security/trivy-fs)    ; un check puntual

  Uso por CLI:
    clojure -M:harness all | fast | list | lint | fmt | security | tests | arch"
  (:require [clojure.java.io :as io]
            [clojure.java.shell :as sh]
            [clojure.string :as str]
            [clojure.test :as t]
            [clojure.tools.namespace.find :as find]
            [vallum.system :as system]))

;; ---- Resultados -------------------------------------------------------------

(def statuses #{::pass ::fail ::skip})

(defn result
  "Construye un resultado de check normalizado."
  [id status summary & [details]]
  {:pre [(statuses status)]}
  (cond-> {:id id :status status :summary summary}
    details (assoc :details details)))

(defn passed?
  [{:keys [status]}]
  (= status ::pass))

(defn failed?
  [{:keys [status]}]
  (= status ::fail))

;; ---- Fases ------------------------------------------------------------------

(def phase-order [:M0 :M1 :M2 :M3 :M4 :M5])

(defn current-phase
  []
  (:phase system/version))

(defn phase-rank
  [phase]
  (.indexOf ^java.util.List phase-order phase))

(defn- phase-at-least?
  [required]
  (>= (phase-rank (current-phase)) (phase-rank required)))

;; ---- Ejecución de procesos --------------------------------------------------

(defn- sh*
  "Ejecuta un comando sin lanzar excepciones. Devuelve {:exit :out :err}."
  [& args]
  (try
    (apply sh/sh args)
    (catch Exception e
      {:exit -1 :out "" :err (ex-message e)})))

(defn- trivy-binary
  "Localiza el binario trivy: PATH o ~/.local/bin. nil si no existe."
  []
  (let [local (io/file (System/getProperty "user.home") ".local/bin/trivy")]
    (or (when (zero? (:exit (sh* "trivy" "--version")))
          "trivy")
        (when (.canExecute local)
          (.getPath local)))))

;; ---- Checks -----------------------------------------------------------------

(defn check-kondo
  "Lint con clj-kondo vía deps.edn (no requiere binario instalado).
  Warnings visibles pero no bloquean (--fail-level error)."
  []
  (println "🔍 clj-kondo...")
  (let [{:keys [exit out err]} (sh* "clojure" "-M:kondo" "--lint" "src" "test" "--fail-level" "error")]
    (if (zero? exit)
      (result :lint/kondo ::pass "sin errores de lint")
      (result :lint/kondo ::fail "lint falló" (str out err)))))

(defn check-cljfmt
  "Verifica el formateo con cljfmt vía deps.edn."
  []
  (println "🎨 cljfmt...")
  (let [{:keys [exit out err]} (sh* "clojure" "-M:fmt" "check" "src" "test")]
    (if (zero? exit)
      (result :format/cljfmt ::pass "formato correcto")
      (result :format/cljfmt ::fail "formato incorrecto (correr: clojure -M:fmt fix src test)"
              (str out err)))))

(defn check-trivy-fs
  "Escaneo de filesystem con Trivy: vulnerabilidades HIGH/CRITICAL,
  misconfigurations y secrets. Salta si el binario no está instalado."
  []
  (println "🛡️  trivy fs...")
  (if-let [trivy (trivy-binary)]
    (let [{:keys [exit out]} (sh* trivy "fs"
                                  "--scanners" "vuln,misconfig,secret"
                                  "--severity" "HIGH,CRITICAL"
                                  "--exit-code" "1"
                                  ".")]
      (if (zero? exit)
        (result :security/trivy-fs ::pass "sin vulnerabilidades HIGH/CRITICAL ni secrets")
        (result :security/trivy-fs ::fail "vulnerabilidades/misconfig/secrets encontrados" out)))
    (result :security/trivy-fs ::skip
            "trivy no instalado (ver bin/install-trivy.sh)")))

(defn check-trivy-config
  "Escaneo de configuración (IaC/dockerfiles) con Trivy. No necesita DB."
  []
  (println "⚙️  trivy config...")
  (if-let [trivy (trivy-binary)]
    (let [{:keys [exit out]} (sh* trivy "config" "--exit-code" "1" ".")]
      (if (zero? exit)
        (result :security/trivy-config ::pass "configuración limpia")
        (result :security/trivy-config ::fail "misconfigurations encontradas" out)))
    (result :security/trivy-config ::skip
            "trivy no instalado (ver bin/install-trivy.sh)")))

(defn- test-summary->status
  [id label {:keys [fail error]}]
  (if (pos? (+ fail error))
    (result id ::fail (str label ": " (+ fail error) " fallo(s)"))
    (result id ::pass (str label " OK"))))

(defn check-unit-tests
  "Corre TODA la suite bajo test/ en este mismo proceso vía vallum.run-all
  (descubre namespaces automáticamente). La suite de arquitectura también
  corre acá; el check dedicado :conventions/architecture la reporta aparte
  para feedback granular."
  []
  (println "🧪 tests...")
  (require 'vallum.run-all)
  (let [run-fn @(resolve 'vallum.run-all/run-suite)]
    (test-summary->status :tests/unit "tests" (run-fn))))

(defn check-architecture
  "Tests de arquitectura y convenciones (docs/ARCHITECTURE.md §4)."
  []
  (println "🏗️  arquitectura y convenciones...")
  (require 'vallum.architecture-test)
  (let [summary (t/run-tests 'vallum.architecture-test)]
    (test-summary->status :conventions/architecture "arquitectura" summary)))

(defn- subdir-test-nss
  "Namespaces de test bajo test/vallum/<subdir>/. Devuelve [] si el dir
  no existe o está vacío."
  [subdir]
  (let [d (io/file "test" "vallum" (name subdir))]
    (when (.isDirectory d)
      (vec (sort (find/find-namespaces [d]))))))

(defn check-subdir-suite
  "Check para suites futuras (generativa/adversarial, docs/ARCHITECTURE.md §6):
  descubre y corre todos los tests bajo test/vallum/<subdir>/.
  Si la fase actual aún no alcanzó el hito de la suite, o el dir está vacío,
  devuelve :skip."
  [id subdir milestone]
  (println "🎲" (name id) "...")
  (cond
    (not (phase-at-least? milestone))
    (result id ::skip (str "disponible desde " (name milestone)))

    (empty? (subdir-test-nss subdir))
    (result id ::skip (str "sin suites todavía (agregar tests en test/vallum/" (name subdir) "/)"))

    :else
    (let [nss (subdir-test-nss subdir)]
      (doseq [ns nss] (require ns))
      (test-summary->status id (name subdir) (apply t/run-tests nss)))))

;; ---- Registro de checks -----------------------------------------------------

(def registry
  "Orden canónico de ejecución. Para agregar un check: escribir la función,
  agregarla acá con su hito, y listo — REPL, CLI, pre-commit y CI la heredan."
  [{:id :lint/kondo                  :label "lint (clj-kondo)"      :fn check-kondo}
   {:id :format/cljfmt               :label "formato (cljfmt)"      :fn check-cljfmt}
   {:id :security/trivy-fs           :label "trivy fs"              :fn check-trivy-fs}
   {:id :security/trivy-config       :label "trivy config"          :fn check-trivy-config}
   {:id :conventions/architecture    :label "arquitectura/docs"     :fn check-architecture}
   {:id :tests/unit                  :label "tests unitarios"       :fn check-unit-tests}
   {:id :tests/generative            :label "tests generativos"     :milestone :M2
    :fn #(check-subdir-suite :tests/generative :generative :M2)}
   {:id :tests/adversarial           :label "suite adversarial"     :milestone :M2
    :fn #(check-subdir-suite :tests/adversarial :adversarial :M2)}])

(defn select-checks
  "Filtra el registro por selectores: un selector matchea el id completo
  (:lint/kondo) o su namespace (:lint). Sin selectores ⇒ todo el registro."
  [selectors]
  (let [sel (set selectors)]
    (if (empty? sel)
      registry
      (filterv (fn [{:keys [id]}]
                 (or (contains? sel id)
                     (some #(= % (keyword (namespace id))) sel)))
               registry))))

(defn run-checks
  "Ejecuta checks y devuelve un VECTOR ordenado de resultados (datos).
  Selectors opcionales: [:lint], [:security], [:lint/kondo]..."
  ([] (run-checks []))
  ([selectors]
   (mapv (fn [{:keys [id fn]}]
           (try
             (fn)
             (catch Exception e
               (result id ::fail "excepción en el check" (pr-str e)))))
         (select-checks selectors))))

(defn run-one
  "Un solo check por id: (run-one :lint/kondo)."
  [id]
  (first (run-checks [id])))

;; ---- Reporte ----------------------------------------------------------------

(def ^:private status-icon {::pass "✅" ::fail "❌" ::skip "⏭️ "})

(defn print-report!
  "Imprime un reporte legible de los resultados. Los detalles de los checks
  que fallaron se muestran completos."
  [results]
  (println)
  (println "═══ Vallum · harness · fase" (name (current-phase)) "═══")
  (doseq [{:keys [id status summary details]} results]
    (println (str (status-icon status) " " (name id) " — " summary))
    (when (and details (failed? {:status status}))
      (println (str "    " (str/replace (str/trim (str details)) #"\n" "\n    ")))))
  (println)
  (println (str (count (filter passed? results)) " pass / "
                (count (filter failed? results)) " fail / "
                (count (remove #(contains? #{::pass ::fail} (:status %)) results)) " skip"))
  results)

(defn exit-code
  "0 si nada falló (los :skip no bloquean), 1 en caso contrario."
  [results]
  (if (some failed? results) 1 0))

(defn run-and-report!
  "Conveniencia REPL/CLI: corre, reporta y devuelve los resultados."
  ([] (run-and-report! []))
  ([selectors]
   (print-report! (run-checks selectors))))

;; ---- Presets ----------------------------------------------------------------

(defn run-fast!
  "Feedback instantáneo para pre-commit: lint + formato + arquitectura + tests.
  Sin Trivy ni subprocesos lentos."
  []
  (run-and-report! [:lint :format :conventions :tests/unit]))

(defn run-security!
  "Solo escaneos de seguridad (Trivy)."
  []
  (run-and-report! [:security]))

;; ---- CLI --------------------------------------------------------------------

(defn- print-usage!
  []
  (println "Uso: clojure -M:harness <comando>")
  (println)
  (println "Comandos:")
  (println "  all        suite completa aplicable a la fase actual")
  (println "  fast       lint + formato + arquitectura + tests (pre-commit)")
  (println "  security   solo Trivy (fs + config)")
  (println "  lint       solo clj-kondo")
  (println "  fmt        solo cljfmt")
  (println "  tests      solo tests unitarios")
  (println "  arch       solo arquitectura/convenciones")
  (println "  list       lista los checks registrados y sus hitos")
  (println)
  (println "Checks registrados:")
  (doseq [{:keys [id label milestone]} registry]
    (println (str "  " id " — " label
                  (when milestone (str " (desde " (name milestone) ")"))))))

(defn -main
  [& args]
  (let [cmd (first args)
        results (case cmd
                  "all"      (run-and-report!)
                  "fast"     (run-fast!)
                  "security" (run-security!)
                  "lint"     (run-and-report! [:lint])
                  "fmt"      (run-and-report! [:format])
                  "tests"    (run-and-report! [:tests/unit])
                  "arch"     (run-and-report! [:conventions])
                  "list"     (do (print-usage!) [])
                  (do (print-usage!) (System/exit 1)))]
    (System/exit (exit-code results))))

(comment
 ;; REPL:
  (require '[vallum.harness :as h])
  (h/run-checks)                          ; datos crudos
  (h/run-fast!)                           ; feedback instantáneo
  (h/run-security!)
  (h/run-one :lint/kondo)
  (h/print-report! (h/run-checks)))
