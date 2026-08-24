(ns vallum.harness-test
  "Meta-tests: the harness itself is code and gets tested.
  Only covers pure logic (registry, selection, reporting) — never runs real
  checks here to keep the suite non-recursive and fast."
  (:require [clojure.test :refer [deftest is testing]]
            [vallum.harness :as h]))

(deftest full-registry
  (let [ids (mapv :id h/registry)]
    (is (pos? (count ids)) "the registry cannot be empty")
    (is (= ids (distinct ids)) "duplicate ids in the registry")
    (doseq [{:keys [id label fn milestone]} h/registry]
      (testing (str id)
        (is (keyword? id))
        (is (string? label))
        (ifn? fn)
        (when milestone
          (is (contains? #{:M0 :M1 :M2 :M3 :M4 :M5} milestone)))))))

(deftest select-filters-by-id-and-by-namespace
  (is (= (count h/registry) (count (h/select-checks []))) "no selectors ⇒ everything")
  (is (= [:lint/kondo] (mapv :id (h/select-checks [:lint/kondo]))))
  (is (= #{:security/trivy-fs :security/trivy-config}
         (set (map :id (h/select-checks [:security])))))
  (is (empty? (h/select-checks [:does-not-exist]))))

(deftest result-validates-and-normalizes
  (let [r (h/result :x/y ::h/pass "ok" "detail")]
    (is (= {:id :x/y :status ::h/pass :summary "ok" :details "detail"} r)))
  (is (thrown? AssertionError (h/result :x/y ::made-up-status "boom"))))

(deftest exit-code-semantics
  ;; :skip doesn't block; only :fail produces exit code 1.
  (is (zero? (h/exit-code [])))
  (is (zero? (h/exit-code [(h/result :a ::h/pass "") (h/result :b ::h/skip "")])))
  (is (= 1 (h/exit-code [(h/result :a ::h/pass "") (h/result :b ::h/fail "")]))))

(deftest phases-are-ranked
  (is (< (h/phase-rank :M0) (h/phase-rank :M5)))
  (is (contains? #{:M0 :M1 :M2 :M3 :M4 :M5 :M6} (h/current-phase))))
