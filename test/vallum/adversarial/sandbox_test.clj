(ns vallum.adversarial.sandbox-test
  "Adversarial attack suite against the dynamic rule sandbox (PROPOSAL §5).

  Every test in this namespace must verify that the system rejects the
  attack and (when applicable) leaves a record of the attempt.

  Attack classes (from PROPOSAL §6 and ARCHITECTURE §6):
  unknown keys · unknown actions · malformed EDN · unexpected nesting · type
  confusion · giant integers · negative or zero TTL · NaN/weird numeric
  values · duplicate fields · hostile unicode · oversized strings · unexpected
  EDN tags · attempted :open-port / :accept / :flush (unexpressible)."
  (:require [clojure.test :refer [deftest is testing]]
            [vallum.validate :as v]))

(def sandbox
  {:actions #{:drop-ip :rate-limit}
   :default-ttl "30m"
   :max-ttl "24h"
   :max-active 50})

(def base-rule
  {:action :drop-ip
   :ip "[IP_ADDRESS]"
   :ttl "30m"
   :reason "test"
   :source :agent/gemini
   :ts "2026-08-22T20:15:00Z"})

;; ---- Rejection helpers --------------------------------------------------------

(defn assert-rejected
  "Asserts that validate-dynamic-rule returns a non-nil error for the given rule."
  [rule & [expected-error]]
  (let [result (v/validate-dynamic-rule rule sandbox)]
    (is (some? result) (str "Expected rejection, got nil for: " (pr-str rule)))
    (when expected-error
      (is (= expected-error (:error result))
          (str "Expected error " expected-error ", got " (:error result)
               " for: " (pr-str rule)))))
  (when expected-error
    rule))

;; ---- Unknown keys / actions (unexpressible) -----------------------------------

(deftest unknown-action-accept-rejected
  (assert-rejected (assoc base-rule :action :accept) :invalid-dynamic-rule))

(deftest unknown-action-flush-rejected
  (assert-rejected (assoc base-rule :action :flush) :invalid-dynamic-rule))

(deftest unknown-action-open-port-rejected
  (assert-rejected (assoc base-rule :action :open-port) :invalid-dynamic-rule))

(deftest unknown-action-delete-rejected
  (assert-rejected (assoc base-rule :action :delete) :invalid-dynamic-rule))

(deftest unknown-action-allow-rejected
  (assert-rejected (assoc base-rule :action :allow) :invalid-dynamic-rule))

(deftest unknown-action-bogus-rejected
  (assert-rejected (assoc base-rule :action :bogus) :invalid-dynamic-rule))

(deftest unknown-key-rejected
  (assert-rejected (assoc base-rule :unknown-key "injection") :unknown-keys))

(deftest extra-nesting-rejected
  (assert-rejected (assoc base-rule :nested {:inner "value"}) :unknown-keys))

;; ---- TTL attacks ---------------------------------------------------------------

(deftest negative-ttl-rejected
  (assert-rejected (assoc base-rule :ttl "-30m") :invalid-ttl))

(deftest zero-ttl-rejected
  (assert-rejected (assoc base-rule :ttl "0m") :invalid-ttl))

(deftest ttl-exceeding-max-rejected
  (assert-rejected (assoc base-rule :ttl "48h") :ttl-exceeded))

(deftest ttl-with-weird-format-rejected
  (assert-rejected (assoc base-rule :ttl "1.5h") :invalid-ttl)
  (assert-rejected (assoc base-rule :ttl "NaN") :invalid-ttl)
  (assert-rejected (assoc base-rule :ttl "00s") :invalid-ttl))

;; ---- Numeric attacks -----------------------------------------------------------

(deftest giant-integer-ttl-rejected
  (assert-rejected (assoc base-rule :ttl "999999999999999h") :ttl-exceeded))

(deftest structural-type-confusion-rejected
  (assert-rejected (assoc base-rule :ttl 30) :invalid-dynamic-rule)
  (assert-rejected (assoc base-rule :action "drop-ip") :invalid-dynamic-rule)
  (assert-rejected (assoc base-rule :ip 12345) :invalid-dynamic-rule))

;; ---- Malformed structure -------------------------------------------------------

(deftest rule-missing-required-keys-rejected
  (assert-rejected {:action :drop-ip} :invalid-dynamic-rule)
  (assert-rejected {:ip "[IP_ADDRESS]"} :invalid-dynamic-rule))

(deftest rule-with-nil-values-rejected
  (assert-rejected (assoc base-rule :ip nil) :invalid-dynamic-rule))

(deftest rule-with-empty-strings-rejected
  (assert-rejected (assoc base-rule :ip "") :empty-field)
  (assert-rejected (assoc base-rule :ttl "") :empty-field)
  (assert-rejected (assoc base-rule :reason "") :empty-field))

;; ---- Hostile unicode / long strings --------------------------------------------
;; The validate layer accepts any valid Clojure string (unicode is valid data).
;; String rejection happens at nftables emit or the runtime boundary.

(deftest oversized-strings-rejected
  (let [long-reason (apply str (repeat 5000 "A"))
        err (v/validate-dynamic-rule (assoc base-rule :reason long-reason) sandbox)]
    (is (some? err))
    (is (= :field-too-long (:error err)))))

;; ---- Edge cases: valid boundary values ----------------------------------------
;; These should PASS — they're at the boundary but still valid.

(deftest ttl-equals-max-ttl-valid
  (is (nil? (v/validate-dynamic-rule (assoc base-rule :ttl "24h") sandbox))))

(deftest minimal-valid-duration-valid
  (is (nil? (v/validate-dynamic-rule (assoc base-rule :ttl "1s") sandbox))))

(deftest valid-ipv4-formats-valid
  (is (nil? (v/validate-dynamic-rule (assoc base-rule :ip "[IP_ADDRESS]") sandbox))))

(deftest boundary-string-length-valid
  (let [max-reason (apply str (repeat 4096 "A"))
        err (v/validate-dynamic-rule (assoc base-rule :reason max-reason) sandbox)]
    (is (nil? err) (str "4096-char string should be valid but got: " err))))

;; ---- Inexpressible actions (gold criterion) ------------------------------------
;; The proposal states: "open port 22 to the Internet" fails because :open-port
;; does not exist in the language, not because a filter detects it.

(deftest inexpressible-actions-fail-by-definition
  (doseq [action [:open-port :accept :flush :delete :ignore :bypass]]
    (let [rule (assoc base-rule :action action)
          result (v/validate-dynamic-rule rule sandbox)]
      (is (some? result)
          (str "Action " (pr-str action) " should be rejected — it does not exist"))
      (is (= :invalid-dynamic-rule (:error result))
          (str "Action " (pr-str action) " fails because :action not in "
               "#{:drop-ip :rate-limit}, not because a filter detects it")))))
