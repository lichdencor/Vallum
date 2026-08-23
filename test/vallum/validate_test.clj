(ns vallum.validate-test
  "Tests for vallum.validate: duration parsing, dynamic rule validation,
  and IR-level invariants (I0–I3)."
  (:require [clojure.spec.alpha :as s]
            [clojure.test :refer [deftest is testing]]
            [vallum.validate :as v]))

;; ---- Duration parsing ---------------------------------------------------------

(deftest parse-valid-durations
  (testing "seconds"
    (is (= 30 (v/duration->seconds "30s")))
    (is (= 1 (v/duration->seconds "1s"))))
  (testing "minutes"
    (is (= 600 (v/duration->seconds "10m")))
    (is (= 3600 (v/duration->seconds "60m"))))
  (testing "hours"
    (is (= 3600 (v/duration->seconds "1h")))
    (is (= 86400 (v/duration->seconds "24h"))))
  (testing "days"
    (is (= 86400 (v/duration->seconds "1d")))
    (is (= 604800 (v/duration->seconds "7d")))))

(deftest reject-invalid-durations
  (is (nil? (v/duration->seconds nil)))
  (is (nil? (v/duration->seconds "")))
  (is (nil? (v/duration->seconds "abc")))
  (is (nil? (v/duration->seconds "30")))
  (is (nil? (v/duration->seconds "30x")))
  (is (nil? (v/duration->seconds "0m")))
  (is (nil? (v/duration->seconds "1.5h")))
  (is (nil? (v/duration->seconds "-30m"))))

(deftest valid-duration-predicate
  (is (v/valid-duration? "30m"))
  (is (v/valid-duration? "1h"))
  (is (not (v/valid-duration? "abc")))
  (is (not (v/valid-duration? nil))))

(deftest duration-comparison
  (is (v/duration<=? "1m" "1h"))
  (is (v/duration<=? "1h" "1h"))
  (is (v/duration<=? "30m" "1h"))
  (is (not (v/duration<=? "1h" "30m")))
  (is (nil? (v/duration<=? "abc" "1h")))
  (is (nil? (v/duration<=? "1h" "abc"))))

;; ---- Sandbox and dynamic rule fixtures ----------------------------------------

(def valid-sandbox
  {:actions #{:drop-ip :rate-limit}
   :default-ttl "30m"
   :max-ttl "24h"
   :max-active 50})

(def valid-rule
  {:action :drop-ip
   :ip "[IP_ADDRESS]"
   :ttl "45m"
   :reason "SSH brute-force: 200 attempts/min (alert #4821)"
   :source :agent/gemini
   :ts "2026-08-22T20:15:00Z"})

(def rate-limit-rule
  (assoc valid-rule :action :rate-limit))

;; ---- validate-dynamic-rule ----------------------------------------------------

(deftest valid-rule-passes
  (is (nil? (v/validate-dynamic-rule valid-rule valid-sandbox))))

(deftest valid-rate-limit-passes
  (is (nil? (v/validate-dynamic-rule rate-limit-rule valid-sandbox))))

(deftest invalid-sandbox-rejected
  (let [err (v/validate-dynamic-rule valid-rule {:actions #{:drop-ip}})]
    (is (some? err))
    (is (= :invalid-sandbox-spec (:error err)))))

(deftest structurally-invalid-rule-rejected
  (let [err (v/validate-dynamic-rule {:action :drop-ip :ip "[IP_ADDRESS]"} valid-sandbox)]
    (is (some? err))
    (is (= :invalid-dynamic-rule (:error err)))))

(deftest action-not-allowed-rejected
  (let [sandbox {:actions #{:rate-limit} :default-ttl "30m" :max-ttl "24h" :max-active 50}
        err (v/validate-dynamic-rule valid-rule sandbox)]
    (is (some? err))
    (is (= :action-not-allowed (:error err)))))

(deftest invalid-ttl-format-rejected
  (let [rule (assoc valid-rule :ttl "bad-ttl")
        err (v/validate-dynamic-rule rule valid-sandbox)]
    (is (some? err))
    (is (= :invalid-ttl (:error err)))))

(deftest ttl-exceeds-max-rejected
  (let [rule (assoc valid-rule :ttl "48h")
        err (v/validate-dynamic-rule rule valid-sandbox)]
    (is (some? err))
    (is (= :ttl-exceeded (:error err)))))

(deftest ttl-equals-max-is-valid
  (let [rule (assoc valid-rule :ttl "24h")
        err (v/validate-dynamic-rule rule valid-sandbox)]
    (is (nil? err))))

;; ---- validate-dynamic-rules ---------------------------------------------------

(deftest multiple-valid-rules-pass
  (let [rules [valid-rule rate-limit-rule]]
    (is (nil? (v/validate-dynamic-rules rules valid-sandbox)))))

(deftest any-invalid-rule-causes-failure
  (let [rules [valid-rule (assoc valid-rule :action :flush)]]
    (is (some? (v/validate-dynamic-rules rules valid-sandbox)))))

;; ---- validate-ir --------------------------------------------------------------

(deftest valid-ir-passes
  (let [ir {:ir/version 1
            :name "test"
            :zones {:wan {:iface "eth0"}}
            :services {:ssh {:proto :tcp :port 22}}
            :rules [{:action :allow :from :wan :to :wan}]
            :sandboxes {:containment valid-sandbox}}]
    (is (nil? (v/validate-ir ir)))))

(deftest invalid-ir-schema-rejected
  (let [ir {:ir/version 999 :name "bad"}]
    (is (some? (v/validate-ir ir)))))

(deftest sandbox-actions-required
  (let [ir {:ir/version 1
            :name "test"
            :zones {}
            :services {}
            :rules []
            :sandboxes {:empty {:actions #{} :default-ttl "30m" :max-ttl "24h" :max-active 50}}}]
    (is (some? (v/validate-ir ir)))))

(deftest sandbox-max-active-must-be-positive
  (let [ir {:ir/version 1
            :name "test"
            :zones {}
            :services {}
            :rules []
            :sandboxes {:bad {:actions #{:drop-ip} :default-ttl "30m" :max-ttl "24h" :max-active 0}}}]
    (is (some? (v/validate-ir ir)))))

(deftest sandbox-ttl-must-be-valid-duration
  (let [ir {:ir/version 1
            :name "test"
            :zones {}
            :services {}
            :rules []
            :sandboxes {:bad {:actions #{:drop-ip} :default-ttl "bad" :max-ttl "bad" :max-active 10}}}]
    (is (some? (v/validate-ir ir)))))
