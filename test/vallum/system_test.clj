(ns vallum.system-test
  "Minimal contract of the system metadata namespace."
  (:require [clojure.test :refer [deftest is]]
            [vallum.system :as system]))

(deftest version-is-a-complete-map
  (is (map? system/version))
  (doseq [k [:name :major :minor :phase]]
    (is (contains? system/version k) (str "missing key " k))))

(deftest phase-within-documented-milestones
  (is (contains? #{:M0 :M1 :M2 :M3 :M4 :M5} (:phase system/version))
      "the phase must be an M0–M5 milestone from docs/PROPOSAL.md §8"))

(deftest project-name
  (is (= "vallum" (:name system/version))))
