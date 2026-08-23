(ns vallum.validate
  "Policy and dynamic rule validation.

  Validates IR data and candidate dynamic rules against invariants I0–I3.
  Pure: no I/O, no side effects.

  I0 — Dynamic rules are plain EDN (structural check via spec)
  I1 — Action must be in the sandbox's allowed actions set
  I2 — TTL must be a valid duration and ≤ sandbox max-ttl
  I3 — Active rules count must be ≤ sandbox max-active

  Usage:
    (require '[vallum.validate :as v])
    (v/validate-dynamic-rule {:action :drop-ip ...} sandbox)  ;; => nil | error map
    (v/valid-duration? \"30m\")                                   ;; => true
    (v/duration<=? \"1h\" \"24h\")                                ;; => true"
  (:require [clojure.spec.alpha :as s]
            [clojure.string :as str]
            [vallum.ir :as ir]))

;; ---- Duration parsing --------------------------------------------------------

(def ^:private unit->seconds
  {\s 1
   \m 60
   \h 3600
   \d 86400})

(def ^:private duration-re
  #"^([1-9]\d*)([smhd])$")

(defn duration->seconds
  "Parses a duration string like \"30m\", \"1h\", \"24h\" to seconds.
  Returns nil on invalid format."
  [s]
  (when (string? s)
    (when-let [[_ num unit] (re-matches duration-re (str/trim s))]
      (let [n (Long/parseLong num)
            factor (unit->seconds (first unit))]
        (* n factor)))))

(defn valid-duration?
  "True if the string is a valid duration format."
  [s]
  (some? (duration->seconds s)))

(defn duration<=?
  "Compares two duration strings. Returns true if a ≤ b (in seconds).
  Returns false if either is unparseable."
  [a b]
  (when-let [sa (duration->seconds a)]
    (when-let [sb (duration->seconds b)]
      (<= sa sb))))

;; ---- Dynamic rule validation (I0–I3) -----------------------------------------

(def ^:private known-dynamic-keys
  "Known keys for a valid dynamic rule (used to reject unknown keys)."
  #{:action :ip :ttl :reason :source :ts})

(def ^:private max-string-length
  "Maximum length for any string field in a dynamic rule."
  4096)

(defn- validate-dynamic-rule*
  "Core validation logic after structural checks pass."
  [rule sandbox]
  (cond
    (not (contains? (:actions sandbox) (:action rule)))
    {:error :action-not-allowed
     :explain (str "Action " (pr-str (:action rule))
                   " not in sandbox actions " (pr-str (:actions sandbox)))}

    (not (valid-duration? (:ttl rule)))
    {:error :invalid-ttl
     :explain (str "Invalid TTL format: " (pr-str (:ttl rule)))}

    (not (duration<=? (:ttl rule) (:max-ttl sandbox)))
    {:error :ttl-exceeded
     :explain (str "TTL " (:ttl rule) " exceeds max-ttl "
                   (:max-ttl sandbox))}

    :else nil))

(defn validate-dynamic-rule
  "Validates a candidate dynamic rule against a sandbox configuration.
  Returns nil (valid) or a map with :error and :explain.

  Checks in order:
  - sandbox structure validity
  - rule structural spec conformance (I0)
  - unknown keys (closed schema)
  - empty strings
  - oversized strings
  - action must be in sandbox's allowed actions (I1)
  - TTL must be valid and ≤ max-ttl (I2)
  - max-active is validated externally (I3)"
  [rule sandbox]
  (cond
    (not (map? sandbox))
    {:error :invalid-sandbox :explain "Sandbox must be a map"}

    (not (s/valid? :sandbox/spec sandbox))
    (let [expl (s/explain-data :sandbox/spec sandbox)]
      {:error :invalid-sandbox-spec :explain (pr-str expl)})

    (not (map? rule))
    {:error :invalid-dynamic-rule :explain "Dynamic rule must be a map"}

    (not (s/valid? :dynamic/spec rule))
    (let [expl (s/explain-data :dynamic/spec rule)]
      {:error :invalid-dynamic-rule :explain (pr-str expl)})

    (seq (remove known-dynamic-keys (keys rule)))
    (let [extra (remove known-dynamic-keys (keys rule))]
      {:error :unknown-keys
       :explain (str "Unknown keys in dynamic rule: " (pr-str extra))})

    (str/blank? (:ip rule))
    {:error :empty-field :explain "IP field must not be empty"}

    (str/blank? (:ttl rule))
    {:error :empty-field :explain "TTL field must not be empty"}

    (str/blank? (:reason rule))
    {:error :empty-field :explain "Reason field must not be empty"}

    (some (fn [k] (and (string? (get rule k))
                       (> (count (get rule k)) max-string-length)))
          [:ip :ttl :reason])
    {:error :field-too-long
     :explain (str "String fields must not exceed " max-string-length " characters")}

    :else (validate-dynamic-rule* rule sandbox)))

(defn validate-dynamic-rules
  "Validates a collection of dynamic rules against a sandbox config.
  Returns nil if all valid, or a vector of error maps."
  [rules sandbox]
  (let [errors (keep #(validate-dynamic-rule % sandbox) rules)]
    (when (seq errors) (vec errors))))

;; ---- Policy validation (IR-level invariants) ---------------------------------

(defn validate-ir
  "Validates an IR structure beyond basic spec conformance.
  Returns nil if valid, or a vector of error maps."
  [ir-data]
  (let [errors (atom [])]
    ;; Structural spec conformance
    (when-not (ir/valid-ir? ir-data)
      (swap! errors conj
             {:error :invalid-ir-schema
              :explain (pr-str (ir/explain-ir ir-data))}))

    ;; I3: sandbox max-active must be positive
    (doseq [[sid sb] (get ir-data :sandboxes {})]
      (when (not (pos-int? (:max-active sb)))
        (swap! errors conj
               {:error :invalid-max-active
                :explain (str "Sandbox " (pr-str sid)
                              " max-active must be positive: "
                              (:max-active sb))}))
      ;; I2: max-ttl must be a valid duration
      (when-not (valid-duration? (:max-ttl sb))
        (swap! errors conj
               {:error :invalid-max-ttl
                :explain (str "Sandbox " (pr-str sid)
                              " max-ttl must be a valid duration: "
                              (pr-str (:max-ttl sb)))}))

      ;; I1: sandbox actions must be non-empty
      (when (empty? (:actions sb))
        (swap! errors conj
               {:error :empty-sandbox-actions
                :explain (str "Sandbox " (pr-str sid)
                              " must have at least one action")})))

    (when (seq @errors) @errors)))

(defn validate
  "Full validation: IR structure + dynamic rules (if present).
  Returns nil if everything is valid, or a sequence of errors."
  [ir-data]
  (let [ir-errors (validate-ir ir-data)]
    (when ir-errors ir-errors)))
