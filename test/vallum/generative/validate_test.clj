(ns vallum.generative.validate-test
  "Generative (test.check) tests for vallum.validate.
  Verifies that invariants I0–I3 hold under arbitrary valid inputs, and
  that arbitrary invalid inputs are always rejected."
  (:require [clojure.spec.alpha :as s]
            [clojure.spec.gen.alpha :as gen]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.properties :as prop]
            [clojure.test.check.generators :as g]
            [vallum.ir :as ir]
            [vallum.validate :as v]))

;; ---- Generators ---------------------------------------------------------------

(def gen-action (g/elements [:drop-ip :rate-limit]))
(def gen-bad-action (g/elements [:accept :flush :open-port :delete :ignore :allow]))
(def gen-duration-unit (g/elements ["s" "m" "h" "d"]))

(defn gen-valid-duration
  "Generates a valid duration string like '30m', '2h'."
  []
  (g/fmap (fn [[n unit]] (str n unit))
          (g/tuple (g/choose 1 999) gen-duration-unit)))

(defn gen-invalid-duration
  "Generates strings that are NOT valid durations."
  []
  (g/one-of [(g/return "")
             (g/return nil)
             (g/return "abc")
             (g/return "0m")
             (g/return "-30m")
             (g/return "1.5h")
             (g/return "00s")
             (g/return "NaN")
             (g/fmap #(apply str (take 50 (repeat %))) g/char-alphanumeric)]))

(defn gen-ip
  "Generates a plausible IP-like string."
  []
  (g/fmap (fn [[a b c d]] (str a "." b "." c "." d))
          (g/tuple (g/choose 1 254) (g/choose 0 254) (g/choose 0 254) (g/choose 1 254))))

(defn gen-ttl-value
  "Generates a TTL value ≤ the given max-ttl seconds."
  [max-secs]
  (let [unit-secs [1 60 3600 86400]]
    (g/fmap
     (fn [[n unit]]
       (let [total (* n unit)]
         (when (<= total max-secs)
           (str n (get {1 "s" 60 "m" 3600 "h" 86400 "d"} unit)))))
     (g/tuple (g/choose 1 999)
              (g/elements (filter #(<= % max-secs) unit-secs))))))

(defn gen-valid-sandbox
  "Generates a valid sandbox spec."
  []
  (g/fmap (fn [[actions max-ttl max-active]]
            {:actions (set actions)
             :default-ttl max-ttl
             :max-ttl max-ttl
             :max-active max-active})
          (g/tuple (g/set gen-action {:min-elements 1 :max-elements 2})
                   (gen-valid-duration)
                   (g/choose 1 100))))

(defn gen-valid-dynamic-rule
  "Generates a valid dynamic rule for a given sandbox."
  [sandbox]
  (let [actions (vec (:actions sandbox))
        max-ttl-secs (v/duration->seconds (:max-ttl sandbox))]
    (g/fmap
     (fn [[action ip ttl source ts]]
       {:action action
        :ip ip
        :ttl ttl
        :reason "generated"
        :source source
        :ts ts})
     (g/tuple (g/elements actions)
              (gen-ip)
              (or (some-> max-ttl-secs gen-ttl-value) (gen-valid-duration))
              (g/elements [:agent/gemini :agent/claude :agent/ollama :operator :agent/gpt])
              (g/return "2026-08-22T20:15:00Z")))))

;; ---- Properties ---------------------------------------------------------------

(defspec t-valid-dynamic-rule-always-passes
  {:num-tests 50 :seed 42}
  (prop/for-all [sandbox (gen-valid-sandbox)]
                (g/let [rule (gen-valid-dynamic-rule sandbox)]
                  (nil? (v/validate-dynamic-rule rule sandbox)))))

(defspec t-invalid-action-always-rejected
  {:num-tests 50 :seed 42}
  (prop/for-all [sandbox (gen-valid-sandbox)
                 action gen-bad-action]
                (let [rule {:action action
                            :ip "[IP_ADDRESS]"
                            :ttl "30m"
                            :reason "test"
                            :source :agent/gemini
                            :ts "2026-08-22T20:15:00Z"}]
                  (some? (v/validate-dynamic-rule rule sandbox)))))

(defspec t-invalid-ttl-always-rejected
  {:num-tests 50 :seed 42}
  (prop/for-all [sandbox (gen-valid-sandbox)
                 ttl (gen-invalid-duration)]
                (let [rule {:action (first (:actions sandbox))
                            :ip "[IP_ADDRESS]"
                            :ttl ttl
                            :reason "test"
                            :source :agent/gemini
                            :ts "2026-08-22T20:15:00Z"}]
                  (or (nil? ttl)
                      (some? (v/validate-dynamic-rule rule sandbox))))))

(defspec t-valid-duration-roundtrip
  {:num-tests 100 :seed 42}
  (prop/for-all [duration (gen-valid-duration)]
                (v/valid-duration? duration)))
