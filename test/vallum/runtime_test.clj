(ns vallum.runtime-test
  "Tests for the runtime module: apply, TTL expiry, drift detection,
  budget enforcement, journaling, and the mock backend."
  (:require [clojure.test :refer [deftest is testing use-fixtures]]
            [clojure.java.io :as io]
            [cheshire.core :as json]
            [vallum.runtime :as rt]))

;; ---- Mock Nftables backend ---------------------------------------------------

(defrecord CallLog [calls]
  rt/NftablesBackend
  (check-syntax [_ nft-text]
    (swap! calls conj {:op :check-syntax :text nft-text})
    {:ok true})
  (apply-ruleset! [_ nft-text]
    (swap! calls conj {:op :apply-ruleset :text nft-text})
    {:ok true})
  (add-element! [_ set-name ip timeout-str]
    (swap! calls conj {:op :add-element :set set-name :ip ip :timeout timeout-str})
    {:ok true})
  (delete-element! [_ set-name ip]
    (swap! calls conj {:op :delete-element :set set-name :ip ip})
    {:ok true})
  (list-ruleset [_]
    (swap! calls conj {:op :list-ruleset})
    "table inet vallum { }"))

(defn mock-backend
  "Creates a MockNftables with a fresh call log."
  []
  (->CallLog (atom [])))

(def ^:private sample-sandbox
  {:actions #{:drop-ip :rate-limit} :default-ttl "30m" :max-ttl "24h" :max-active 5})

(def ^:private sample-rule
  {:action :drop-ip :ip "[IP_ADDRESS]" :ttl "45m" :reason "test" :source :agent/test :ts "2026-08-23T12:00:00Z"})

;; ---- Mock backend tests ------------------------------------------------------

(deftest mock-records-calls
  (let [backend (mock-backend)]
    (rt/check-syntax backend "test")
    (rt/apply-ruleset! backend "test")
    (rt/add-element! backend "set1" "1.2.3.4" "1h")
    (rt/delete-element! backend "set1" "1.2.3.4")
    (let [log @(:calls backend)]
      (is (= 4 (count log)))
      (is (= :check-syntax (:op (first log))))
      (is (= :delete-element (:op (last log)))))))

;; ---- init-state --------------------------------------------------------------

(deftest init-state-creates-empty-state
  (let [state (rt/init-state "/tmp/test-journal.jsonl")]
    (is (instance? clojure.lang.Atom state))
    (is (= {} (:active-rules @state)))
    (is (nil? (:expected-hash @state)))
    (is (= "/tmp/test-journal.jsonl" (:journal-path @state)))))

;; ---- apply-policy! ----------------------------------------------------------

(deftest apply-policy-sets-expected-hash
  (let [state (rt/init-state)
        backend (mock-backend)
        nft-text "table inet vallum { chain input { policy drop; } }"
        result (rt/apply-policy! state backend nft-text)]
    (is (:ok result))
    (is (some? (:expected-hash @state)))
    (is (= 1 (count @(:calls backend))))
    (is (= :apply-ruleset (:op (first @(:calls backend)))))))

(deftest apply-policy-skips-hash-on-failure
  (let [state (rt/init-state)
        backend (reify rt/NftablesBackend
                  (check-syntax [_ _] {:ok true})
                  (apply-ruleset! [_ _] {:ok false :error "boom" :exit 1})
                  (add-element! [_ _ _ _] {:ok true})
                  (delete-element! [_ _ _] {:ok true})
                  (list-ruleset [_] ""))
        result (rt/apply-policy! state backend "bad")]
    (is (false? (:ok result)))
    (is (nil? (:expected-hash @state)))))

;; ---- add-dynamic-rule! -------------------------------------------------------

(deftest add-dynamic-rule-succeeds
  (let [state (rt/init-state)
        backend (mock-backend)
        result (rt/add-dynamic-rule! state backend sample-rule :containment sample-sandbox)]
    (is (:ok result))
    (is (some? (:rule-id result)))
    (is (some? (:expires-at result)))
    (is (= 1 (count (:active-rules @state))))
    (is (= 1 (count @(:calls backend))))
    (is (= :add-element (:op (first @(:calls backend)))))))

(deftest add-dynamic-rule-rejects-over-budget
  (let [state (rt/init-state)
        backend (mock-backend)
        small-sandbox (assoc sample-sandbox :max-active 1)]
    ;; First rule should succeed
    (is (:ok (rt/add-dynamic-rule! state backend sample-rule :containment small-sandbox)))
    ;; Second rule should fail budget check
    (let [result (rt/add-dynamic-rule! state backend (assoc sample-rule :ip "5.6.7.8") :containment small-sandbox)]
      (is (false? (:ok result)))
      (is (= :budget-exceeded (:error result))))))

(deftest add-dynamic-rule-rejects-invalid-ttl
  (let [state (rt/init-state)
        backend (mock-backend)
        bad-rule (assoc sample-rule :ttl "forever")
        result (rt/add-dynamic-rule! state backend bad-rule :containment sample-sandbox)]
    (is (false? (:ok result)))
    (is (= :invalid-ttl (:error result)))
    (is (empty? (:active-rules @state)))))

;; ---- remove-dynamic-rule! ----------------------------------------------------

(deftest remove-dynamic-rule-removes-and-logs
  (let [state (rt/init-state)
        backend (mock-backend)
        {:keys [rule-id]} (rt/add-dynamic-rule! state backend sample-rule :containment sample-sandbox)]
    (is (= 1 (count (:active-rules @state))))
    (let [result (rt/remove-dynamic-rule! state backend rule-id)]
      (is (:ok result))
      (is (empty? (:active-rules @state))))
    (is (= 2 (count @(:calls backend))) "add-element + delete-element")))

(deftest remove-nonexistent-rule-fails
  (let [state (rt/init-state)
        backend (mock-backend)
        result (rt/remove-dynamic-rule! state backend "nonexistent")]
    (is (false? (:ok result)))
    (is (= :not-found (:error result)))))

;; ---- expire-due-rules! -------------------------------------------------------

(deftest expire-due-rules-removes-expired
  (let [state (rt/init-state)
        backend (mock-backend)]
    ;; Add a rule with a long TTL
    (rt/add-dynamic-rule! state backend sample-rule :containment sample-sandbox)
    (is (= 1 (count (:active-rules @state))))
    ;; With normal time, nothing expires
    (is (empty? (rt/expire-due-rules! state backend)))
    (is (= 1 (count (:active-rules @state))))
    ;; With binding to far-future time, rule expires
    (binding [rt/*clock* (fn [] Long/MAX_VALUE)]
      (let [expired (rt/expire-due-rules! state backend)]
        (is (= 1 (count expired)))
        (is (= :drop-ip (:action (:rule (first expired)))))))
    (is (empty? (:active-rules @state)))))

(deftest expire-due-rules-only-removes-due
  (let [state (rt/init-state)
        backend (mock-backend)]
    ;; Add two rules with normal TTL
    (rt/add-dynamic-rule! state backend sample-rule :containment sample-sandbox)
    (rt/add-dynamic-rule! state backend (assoc sample-rule :ip "10.0.0.2") :containment sample-sandbox)
    (is (= 2 (count (:active-rules @state))))
    (binding [rt/*clock* (fn [] Long/MAX_VALUE)]
      (is (= 2 (count (rt/expire-due-rules! state backend)))))
    (is (empty? (:active-rules @state)))))

;; ---- drift-check -------------------------------------------------------------

(deftest drift-check-baseline-records-hash
  (let [state (rt/init-state)
        backend (mock-backend)]
    (is (nil? (rt/drift-check state backend)))
    (is (some? (:expected-hash @state)))
    (is (= :list-ruleset (:op (first @(:calls backend)))))))

(deftest drift-check-detects-change
  (let [state (rt/init-state)
        ;; Backend with a controllable list-ruleset
        backend (reify rt/NftablesBackend
                  (check-syntax [_ _] {:ok true})
                  (apply-ruleset! [_ _] {:ok true})
                  (add-element! [_ _ _ _] {:ok true})
                  (delete-element! [_ _ _] {:ok true})
                  (list-ruleset [_]
                    ;; Return different text each call to simulate drift
                    (if (nil? @state) ""
                        (let [current (:expected-hash @state)]
                          (if current "changed ruleset" "original ruleset")))))]
    ;; First call sets baseline
    (is (nil? (rt/drift-check state backend)))
    (let [result (rt/drift-check state backend)]
      (is (some? result))
      (is (:drift-detected result))
      (is (some? (:expected-hash result)))
      (is (some? (:live-hash result))))))

;; ---- budget-status -----------------------------------------------------------

(deftest budget-status-reports-correct-counts
  (let [state (rt/init-state)
        backend (mock-backend)]
    (is (= {:active 0 :max-active 5} (rt/budget-status state :containment sample-sandbox)))
    (rt/add-dynamic-rule! state backend sample-rule :containment sample-sandbox)
    (is (= {:active 1 :max-active 5} (rt/budget-status state :containment sample-sandbox)))
    (rt/add-dynamic-rule! state backend (assoc sample-rule :ip "10.0.0.2") :containment sample-sandbox)
    (is (= {:active 2 :max-active 5} (rt/budget-status state :containment sample-sandbox)))))

;; ---- Journal -----------------------------------------------------------------

(deftest journal-writes-valid-jsonl
  (let [tmp-file (str (java.io.File/createTempFile "vallum-journal" ".jsonl"))
        state (rt/init-state tmp-file)
        backend (mock-backend)]
    (rt/add-dynamic-rule! state backend sample-rule :containment sample-sandbox)
    (let [lines (line-seq (io/reader tmp-file))]
      (is (pos? (count lines)))
      (let [parsed (json/parse-string (first lines) true)]
        (is (= "rule-added" (:event parsed)))
        (is (some? (:ts parsed)))
        (is (= "drop-ip" (:action parsed))))))
  ;; Cleanup
  (doseq [f (.listFiles (java.io.File. "/tmp"))
          :when (re-find #"vallum-journal" (.getName f))]
    (.delete f)))
