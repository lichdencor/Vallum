(ns vallum.run-all
  "Runner unificado de tests: descubre todos los namespaces vallum.* bajo
  test/ (unitarios, generativos, adversariales, arquitectura) y los corre.

  Uso: clojure -M:test            (sale con código 0/1)
  REPL: (require '[vallum.run-all :as run]) (run/run-suite) => resumen"
  (:require [clojure.java.io :as io]
            [clojure.test :as t]
            [clojure.tools.namespace.find :as find]))

(defn- test-namespaces
  "Todos los namespaces de test bajo test/vallum/, ordenados."
  []
  (->> (io/file "test" "vallum")
       (vector)
       (find/find-namespaces)
       (sort)))

(defn run-suite
  "Corre la suite completa. Devuelve el resumen de clojure.test.
  No llama a System/exit (REPL-safe)."
  []
  (let [nss (test-namespaces)]
    (println (str "▶ Vallum tests · " (count nss) " namespaces"))
    (doseq [ns nss] (require ns))
    (apply t/run-tests nss)))

(defn -main
  [& _]
  (let [{:keys [fail error]} (run-suite)]
    (System/exit (if (pos? (+ fail error)) 1 0))))
