(ns vallum.audit-test
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [vallum.ir :as ir]
            [vallum.manifest :as m]
            [vallum.audit :as a]))

;; ---- Known shadowing fixture -------------------------------------------------
;;
;; Rules:
;;   0: allow from lan to wan           (no service = matches all)
;;   1: allow from lan to wan :service ssh   ← SHADOWED by rule 0
;;   2: drop  from wan to lan :service web
;;   3: allow from wan to lan :service web   ← SHADOWED by rule 2
;;   4: allow from lan to wan :service web   ← SHADOWED by rule 0 (broader match)
;;
;; Shadow relationships:
;;   rule 1 ← rule 0 (same zone pair, rule 0 has no service = any)
;;   rule 3 ← rule 2 (same zone pair, same service)
;;   rule 4 ← rule 0 (same zone pair, rule 0 has no service = any)

(def shadow-fixture-rules
  [{:action :allow :from :lan :to :wan}
   {:action :allow :from :lan :to :wan :service :ssh}
   {:action :drop  :from :wan :to :lan :service :web}
   {:action :allow :from :wan :to :lan :service :web}
   {:action :allow :from :lan :to :wan :service :web}])

(def shadow-fixture-zones
  {:wan {:iface "eth0"}
   :lan {:iface "eth1"}})

(def shadow-fixture-services
  {:ssh  {:proto :tcp :port 22}
   :web  {:proto :tcp :port 80}
   :dns  {:proto :tcp :port 53}})

(def shadow-fixture-ir
  (ir/make-ir {:name     "shadow-test"
               :zones    shadow-fixture-zones
               :services shadow-fixture-services
               :rules    shadow-fixture-rules}))

(def shadow-fixture-manifest
  (m/make-manifest shadow-fixture-ir))

(deftest shadowed-rules-detected
  (testing "known fixture: 3 shadow relationships expected"
    (let [findings (a/find-shadowed-rules (:rules shadow-fixture-manifest))]
      (is (= 3 (count findings)))
      (is (every? #(= :shadowed-rule (:type %)) findings)))))

(deftest rule-1-shadowed-by-0
  (testing "rule 1 (allow lan->wan :ssh) shadowed by rule 0 (allow lan->wan any)"
    (let [findings (a/find-shadowed-rules (:rules shadow-fixture-manifest))
          f (first (filter #(= 1 (:index (:shadowed %))) findings))]
      (is f)
      (is (= 0 (:index (:by f))))
      (is (= "allow" (:action (:by f)))))))

(deftest rule-3-shadowed-by-2
  (testing "rule 3 (allow wan->lan :web) shadowed by rule 2 (drop wan->lan :web)"
    (let [findings (a/find-shadowed-rules (:rules shadow-fixture-manifest))
          f (first (filter #(= 3 (:index (:shadowed %))) findings))]
      (is f)
      (is (= 2 (:index (:by f)))))))

(deftest rule-4-shadowed-by-0
  (testing "rule 4 (allow lan->wan :web) shadowed by rule 0 (allow lan->wan any)"
    (let [findings (a/find-shadowed-rules (:rules shadow-fixture-manifest))
          f (first (filter #(= 4 (:index (:shadowed %))) findings))]
      (is f)
      (is (= 0 (:index (:by f)))))))

(deftest non-shadowed-rules-not-reported
  (testing "rules with different zone pairs are not shadowed"
    (let [ir (ir/make-ir {:name     "no-shadow"
                          :zones    {:a {:iface "eth0"} :b {:iface "eth1"}}
                          :services {:x {:proto :tcp :port 80}}
                          :rules    [{:action :allow :from :a :to :b}
                                     {:action :drop  :from :b :to :a :service :x}]})
          manifest (m/make-manifest ir)
          findings (a/find-shadowed-rules (:rules manifest))]
      (is (empty? findings) "different zone pairs should not shadow"))))

(deftest audit-manifest-end-to-end
  (testing "audit-manifest returns findings from known fixture"
    (let [findings (a/audit-manifest shadow-fixture-manifest)]
      (is (= 3 (count findings)))
      (is (every? string? (map :explain findings))))))

(deftest audit-ir-convenience
  (testing "audit-ir wraps manifest building and audit"
    (let [findings (a/audit-ir shadow-fixture-ir)]
      (is (= 3 (count findings))))))

(deftest explain-describes-shadow
  (testing "explain text is human-readable and mentions the rules"
    (let [findings (a/audit-manifest shadow-fixture-manifest)]
      (doseq [f findings]
        (is (str/includes? (:explain f) "shadowed"))
        (is (re-find #"index \d+" (:explain f)))))))
