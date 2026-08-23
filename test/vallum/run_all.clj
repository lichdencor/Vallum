(ns vallum.run-all
  "Unified test runner: discovers all vallum.* namespaces under
  test/ (unit, generative, adversarial, architecture) and runs them.

  Usage: clojure -M:test            (exits with code 0/1)
  REPL: (require '[vallum.run-all :as run]) (run/run-suite) => summary"
  (:require [clojure.java.io :as io]
            [clojure.test :as t]
            [clojure.tools.namespace.find :as find]))

(defn- test-namespaces
  "All test namespaces under test/vallum/, sorted."
  []
  (->> (io/file "test" "vallum")
       (vector)
       (find/find-namespaces)
       (sort)))

(defn run-suite
  "Runs the full suite. Returns the clojure.test summary.
  Does not call System/exit (REPL-safe)."
  []
  (let [nss (test-namespaces)]
    (println (str "▶ Vallum tests · " (count nss) " namespaces"))
    (doseq [ns nss] (require ns))
    (apply t/run-tests nss)))

(defn -main
  [& _]
  (let [{:keys [fail error]} (run-suite)]
    (System/exit (if (pos? (+ fail error)) 1 0))))
