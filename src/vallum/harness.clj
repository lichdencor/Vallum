(ns vallum.harness
  "Vallum quality suite: lint, formatting, security (Trivy), architecture
  conventions and tests — executable from REPL or CLI.

  Philosophy:
  - Each check is a pure-ish function that RETURNS DATA (never prints).
    Reporting is a separate layer, so the REPL consumes results and the CLI
    formats them.
  - Checks are gated by milestone (:phase in vallum.system): what arrives in
    M2 (generative/adversarial tests) is reported as :skip today.
  - Graceful degradation: if Trivy is not installed, the check skips with
    instructions instead of breaking the suite.

  REPL usage:
    (require '[vallum.harness :as h])
    (h/run-checks)                    ; full suite applicable to this phase
    (h/report (h/run-checks))         ; with human-readable output
    (h/run-checks [:lint])            ; subset by id prefix
    (h/run-one :security/trivy-fs)    ; a single check

  CLI usage:
    clojure -M:harness all | fast | list | lint | fmt | security | tests | arch"
  (:require [clojure.java.io :as io]
            [clojure.java.shell :as sh]
            [clojure.string :as str]
            [clojure.test :as t]
            [clojure.tools.namespace.find :as find]
            [vallum.system :as system]))

;; ---- Results -------------------------------------------------------------

(def statuses #{::pass ::fail ::skip})

(defn result
  "Builds a normalized check result."
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

;; ---- Phases ------------------------------------------------------------------

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

;; ---- Process execution --------------------------------------------------

(defn- sh*
  "Runs a command without throwing. Returns {:exit :out :err}."
  [& args]
  (try
    (apply sh/sh args)
    (catch Exception e
      {:exit -1 :out "" :err (ex-message e)})))

(defn- trivy-binary
  "Locates the trivy binary: PATH or ~/.local/bin. nil if missing."
  []
  (let [local (io/file (System/getProperty "user.home") ".local/bin/trivy")]
    (or (when (zero? (:exit (sh* "trivy" "--version")))
          "trivy")
        (when (.canExecute local)
          (.getPath local)))))

;; ---- Checks -----------------------------------------------------------------

(defn check-kondo
  "Lint with clj-kondo via deps.edn (no installed binary needed).
  Warnings are visible but don't block (--fail-level error)."
  []
  (println "🔍 clj-kondo...")
  (let [{:keys [exit out err]} (sh* "clojure" "-M:kondo" "--lint" "src" "test" "--fail-level" "error")]
    (if (zero? exit)
      (result :lint/kondo ::pass "no lint errors")
      (result :lint/kondo ::fail "lint failed" (str out err)))))

(defn check-cljfmt
  "Verifies formatting with cljfmt via deps.edn."
  []
  (println "🎨 cljfmt...")
  (let [{:keys [exit out err]} (sh* "clojure" "-M:fmt" "check" "src" "test")]
    (if (zero? exit)
      (result :format/cljfmt ::pass "formatting OK")
      (result :format/cljfmt ::fail "formatting incorrect (run: clojure -M:fmt fix src test)"
              (str out err)))))

(defn check-trivy-fs
  "Filesystem scan with Trivy: HIGH/CRITICAL vulnerabilities,
  misconfigurations and secrets. Skips if the binary is not installed."
  []
  (println "🛡️  trivy fs...")
  (if-let [trivy (trivy-binary)]
    (let [{:keys [exit out]} (sh* trivy "fs"
                                  "--scanners" "vuln,misconfig,secret"
                                  "--severity" "HIGH,CRITICAL"
                                  "--exit-code" "1"
                                  ".")]
      (if (zero? exit)
        (result :security/trivy-fs ::pass "no HIGH/CRITICAL vulnerabilities nor secrets")
        (result :security/trivy-fs ::fail "vulnerabilities/misconfig/secrets found" out)))
    (result :security/trivy-fs ::skip
            "trivy not installed (see bin/install-trivy.sh)")))

(defn check-trivy-config
  "Configuration (IaC/dockerfiles) scan with Trivy. Needs no DB."
  []
  (println "⚙️  trivy config...")
  (if-let [trivy (trivy-binary)]
    (let [{:keys [exit out]} (sh* trivy "config" "--exit-code" "1" ".")]
      (if (zero? exit)
        (result :security/trivy-config ::pass "configuration clean")
        (result :security/trivy-config ::fail "misconfigurations found" out)))
    (result :security/trivy-config ::skip
            "trivy not installed (see bin/install-trivy.sh)")))

(defn- test-summary->status
  [id label {:keys [fail error]}]
  (if (pos? (+ fail error))
    (result id ::fail (str label ": " (+ fail error) " failure(s)"))
    (result id ::pass (str label " OK"))))

(defn check-unit-tests
  "Runs the WHOLE suite under test/ in this same process via vallum.run-all
  (auto-discovers namespaces). The architecture suite also runs here; the
  dedicated :conventions/architecture check reports it separately for
  granular feedback."
  []
  (println "🧪 tests...")
  (require 'vallum.run-all)
  (let [run-fn @(resolve 'vallum.run-all/run-suite)]
    (test-summary->status :tests/unit "tests" (run-fn))))

(defn check-architecture
  "Architecture and convention tests (docs/ARCHITECTURE.md §4)."
  []
  (println "🏗️  architecture and conventions...")
  (require 'vallum.architecture-test)
  (let [summary (t/run-tests 'vallum.architecture-test)]
    (test-summary->status :conventions/architecture "architecture" summary)))

(defn- subdir-test-nss
  "Test namespaces under test/vallum/<subdir>/. Returns [] if the dir does
  not exist or is empty."
  [subdir]
  (let [d (io/file "test" "vallum" (name subdir))]
    (when (.isDirectory d)
      (vec (sort (find/find-namespaces [d]))))))

(defn check-subdir-suite
  "Check for future suites (generative/adversarial, docs/ARCHITECTURE.md §6):
  discovers and runs all tests under test/vallum/<subdir>/.
  If the current phase has not reached the suite's milestone yet, or the dir
  is empty, returns :skip."
  [id subdir milestone]
  (println "🎲" (name id) "...")
  (cond
    (not (phase-at-least? milestone))
    (result id ::skip (str "available from " (name milestone)))

    (empty? (subdir-test-nss subdir))
    (result id ::skip (str "no suites yet (add tests under test/vallum/" (name subdir) "/)"))

    :else
    (let [nss (subdir-test-nss subdir)]
      (doseq [ns nss] (require ns))
      (test-summary->status id (name subdir) (apply t/run-tests nss)))))

(defn- check-named-test
  "Runs a single test namespace by fully-qualified name string."
  [id ns-name]
  (println "🔬" (name id) "...")
  (try
    (require (symbol ns-name))
    (let [summary (t/run-tests (symbol ns-name))]
      (test-summary->status id ns-name summary))
    (catch Exception e
      (result id ::fail (str "failed to load " ns-name) (ex-message e)))))

;; ---- Check registry -----------------------------------------------------

(def registry
  "Canonical execution order. To add a check: write the function,
  add it here with its milestone, done — REPL, CLI, pre-commit and CI
  inherit it."
  [{:id :lint/kondo                  :label "lint (clj-kondo)"      :fn check-kondo}
   {:id :format/cljfmt               :label "formatting (cljfmt)"   :fn check-cljfmt}
   {:id :security/trivy-fs           :label "trivy fs"              :fn check-trivy-fs}
   {:id :security/trivy-config       :label "trivy config"          :fn check-trivy-config}
   {:id :conventions/architecture    :label "architecture/docs"     :fn check-architecture}
   {:id :tests/unit                  :label "unit tests"            :fn check-unit-tests}
   {:id :tests/generative            :label "generative tests"      :milestone :M2
    :fn #(check-subdir-suite :tests/generative :generative :M2)}
   {:id :tests/adversarial           :label "adversarial suite"     :milestone :M2
    :fn #(check-subdir-suite :tests/adversarial :adversarial :M2)}
   {:id :tests/manifest              :label "manifest tests"       :milestone :M3
    :fn #(check-named-test :tests/manifest "vallum.manifest-test")}
   {:id :tests/audit                 :label "audit tests"           :milestone :M3
    :fn #(check-named-test :tests/audit "vallum.audit-test")}
   {:id :tests/ingest                :label "ingest tests"          :milestone :M4
    :fn #(check-named-test :tests/ingest "vallum.ingest-test")}
   {:id :tests/runtime               :label "runtime tests"         :milestone :M4
    :fn #(check-named-test :tests/runtime "vallum.runtime-test")}
   {:id :tests/bridge                 :label "bridge tests"          :milestone :M5
    :fn #(check-subdir-suite :tests/bridge :bridge :M5)}])

(defn select-checks
  "Filters the registry by selectors: a selector matches the full id
  (:lint/kondo) or its namespace (:lint). No selectors ⇒ whole registry."
  [selectors]
  (let [sel (set selectors)]
    (if (empty? sel)
      registry
      (filterv (fn [{:keys [id]}]
                 (or (contains? sel id)
                     (some #(= % (keyword (namespace id))) sel)))
               registry))))

(defn run-checks
  "Executes checks and returns an ordered VECTOR of results (data).
  Optional selectors: [:lint], [:security], [:lint/kondo]..."
  ([] (run-checks []))
  ([selectors]
   (mapv (fn [{:keys [id fn]}]
           (try
             (fn)
             (catch Exception e
               (result id ::fail "exception in check" (pr-str e)))))
         (select-checks selectors))))

(defn run-one
  "A single check by id: (run-one :lint/kondo)."
  [id]
  (first (run-checks [id])))

;; ---- Report ----------------------------------------------------------------

(def ^:private status-icon {::pass "✅" ::fail "❌" ::skip "⏭️ "})

(defn print-report!
  "Prints a readable report of the results. Details of failed checks are
  shown in full."
  [results]
  (println)
  (println "═══ Vallum · harness · phase" (name (current-phase)) "═══")
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
  "0 if nothing failed (:skip doesn't block), 1 otherwise."
  [results]
  (if (some failed? results) 1 0))

(defn run-and-report!
  "REPL/CLI convenience: runs, reports and returns the results."
  ([] (run-and-report! []))
  ([selectors]
   (print-report! (run-checks selectors))))

;; ---- Presets ----------------------------------------------------------------

(defn run-fast!
  "Instant feedback for pre-commit: lint + format + architecture + tests.
  No Trivy nor slow subprocesses."
  []
  (run-and-report! [:lint :format :conventions :tests/unit]))

(defn run-security!
  "Security scans only (Trivy)."
  []
  (run-and-report! [:security]))

;; ---- CLI --------------------------------------------------------------------

(defn- print-usage!
  []
  (println "Usage: clojure -M:harness <command>")
  (println)
  (println "Commands:")
  (println "  all        full suite applicable to the current phase")
  (println "  fast       lint + formatting + architecture + tests (pre-commit)")
  (println "  security   Trivy only (fs + config)")
  (println "  lint       clj-kondo only")
  (println "  fmt        cljfmt only")
  (println "  tests      unit tests only")
  (println "  arch       architecture/conventions only")
  (println "  list       lists registered checks and their milestones")
  (println)
  (println "Registered checks:")
  (doseq [{:keys [id label milestone]} registry]
    (println (str "  " id " — " label
                  (when milestone (str " (from " (name milestone) ")"))))))

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
  (h/run-checks)                          ; raw data
  (h/run-fast!)                           ; instant feedback
  (h/run-security!)
  (h/run-one :lint/kondo)
  (h/print-report! (h/run-checks)))
