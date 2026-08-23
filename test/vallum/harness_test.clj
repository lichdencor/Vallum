(ns vallum.harness-test
  "Meta-tests: el harness mismo es código y se testea.
  Solo cubre lógica pura (registro, selección, reporte) — nunca ejecuta
  checks reales acá para no volver la suite recursiva ni lenta."
  (:require [clojure.test :refer [deftest is testing]]
            [vallum.harness :as h]))

(deftest registro-integro
  (let [ids (mapv :id h/registry)]
    (is (pos? (count ids)) "el registro no puede estar vacío")
    (is (= ids (distinct ids)) "ids duplicados en el registro")
    (doseq [{:keys [id label fn milestone]} h/registry]
      (testing (str id)
        (is (keyword? id))
        (is (string? label))
        (ifn? fn)
        (when milestone
          (is (contains? #{:M0 :M1 :M2 :M3 :M4 :M5} milestone)))))))

(deftest select-filtra-por-id-y-por-namespace
  (is (= (count h/registry) (count (h/select-checks []))) "sin selectores ⇒ todo")
  (is (= [:lint/kondo] (mapv :id (h/select-checks [:lint/kondo]))))
  (is (= #{:security/trivy-fs :security/trivy-config}
         (set (map :id (h/select-checks [:security])))))
  (is (empty? (h/select-checks [:no-existe]))))

(deftest result-valida-y-normaliza
  (let [r (h/result :x/y ::h/pass "ok" "detalle")]
    (is (= {:id :x/y :status ::h/pass :summary "ok" :details "detalle"} r)))
  (is (thrown? AssertionError (h/result :x/y ::status-inventado "boom"))))

(deftest exit-code-semantica
  ;; Los :skip no bloquean; solo :fail produce código 1.
  (is (zero? (h/exit-code [])))
  (is (zero? (h/exit-code [(h/result :a ::h/pass "") (h/result :b ::h/skip "")])))
  (is (= 1 (h/exit-code [(h/result :a ::h/pass "") (h/result :b ::h/fail "")]))))

(deftest fases-rankeadas
  (is (< (h/phase-rank :M0) (h/phase-rank :M5)))
  (is (contains? #{:M0 :M1 :M2 :M3 :M4 :M5} (h/current-phase))))
