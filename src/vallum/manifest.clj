(ns vallum.manifest
  "Manifest emitter: IR + active dynamic rules → structured data for AI
  bridge and audit. Pure, deterministic (I4).

  The manifest is a versioned snapshot of the policy state that the AI
  receives as context and that the audit layer analyses for conflicts.

  JSON serialization is provided for transport to the AI bridge."
  (:require [cheshire.core :as json]
            [clojure.string :as str]
            [vallum.ir :as ir]))

(def current-version
  "Current version of the manifest schema."
  1)

(defn- rule-summary
  "Converts an IR rule to a compact (JSON-safe) summary map.
  Keywords become strings for JSON compatibility."
  [{:keys [action from to service]}]
  (cond-> {:action (name action)
           :from   (name from)
           :to     (name to)}
    service (assoc :service (if (sequential? service)
                              (mapv name service)
                              (name service)))))

(defn- active-rule-summary
  "Converts a dynamic rule to a compact summary."
  [{:keys [action ip ttl reason source ts]}]
  {:action (name action)
   :ip     ip
   :ttl    ttl
   :reason reason
   :source (if (keyword? source) (name source) (str source))
   :ts     ts})

(defn make-manifest
  "Builds a versioned manifest from an IR structure and optional active
  dynamic rules. Returns a pure-data map suitable for JSON serialization.

  (make-manifest ir)
  (make-manifest ir active-rules)"
  ([ir-data]
   (make-manifest ir-data (:dynamic-rules ir-data [])))
  ([ir-data active-rules]
   (let [sandboxes (get ir-data :sandboxes {})]
     {:manifest/version current-version
      :policy/name      (:name ir-data)
      :ir/version       (:ir/version ir-data)
      :zones            (into {}
                              (map (fn [[k v]] [(name k) v]))
                              (get ir-data :zones {}))
      :services         (into {}
                              (map (fn [[k v]] [(name k) v]))
                              (get ir-data :services {}))
      :rules            (mapv rule-summary (get ir-data :rules []))
      :sandboxes        (vec
                         (for [[sbox-id sbox] (sort-by key sandboxes)
                               :let [sbox-actions (:actions sbox)
                                     sbox-rules (filter #(contains? sbox-actions (:action %))
                                                        active-rules)]]
                           (cond-> {:sandbox/id          (name sbox-id)
                                    :sandbox/actions     (mapv name sbox-actions)
                                    :sandbox/default-ttl (:default-ttl sbox)
                                    :sandbox/max-ttl     (:max-ttl sbox)
                                    :sandbox/max-active  (:max-active sbox)}
                             (seq sbox-rules)
                             (assoc :sandbox/active-rules
                                    (mapv active-rule-summary sbox-rules)))))})))

(defn manifest->json
  "Serializes a manifest to a JSON string. Deterministic: keys are sorted
  for reproducible output (I4)."
  [manifest]
  (json/generate-string manifest
                        {:pretty    true
                         :key-fn    (fn [k] (if (keyword? k) (subs (str k) 1) (str k)))
                         :sort-keys true}))

;; (compile step is separate: users call vallum.compile/compile-forms
;; then pass the result to make-manifest)
