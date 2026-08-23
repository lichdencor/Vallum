(ns vallum.system-test
  "Contrato mínimo del namespace de metadatos del sistema."
  (:require [clojure.test :refer [deftest is]]
            [vallum.system :as system]))

(deftest version-es-un-map-completo
  (is (map? system/version))
  (doseq [k [:name :major :minor :phase]]
    (is (contains? system/version k) (str "falta la clave " k))))

(deftest fase-dentro-de-los-hitos-documentados
  (is (contains? #{:M0 :M1 :M2 :M3 :M4 :M5} (:phase system/version))
      "la fase debe ser un hito M0–M5 de docs/PROPOSAL.md §8"))

(deftest nombre-del-proyecto
  (is (= "vallum" (:name system/version))))
