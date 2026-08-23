(ns vallum.ir
  "Vallum Intermediate Representation (IR).

  Pure, immutable, typed data structure describing a complete firewall
  policy and its dynamic containment constraints.

  The IR is independent of emission backends (nftables, pf, etc.) and is
  the focal point over which the security invariants (I0–I8) are verified.

  Versioned schema (:ir/version 1) with an extensible type registry."
  (:require [clojure.spec.alpha :as s]))

;; ---- Constants and versioning ------------------------------------------------

(def current-version
  "Current version of the IR schema."
  1)

;; ---- Extensible object type registry ----------------------------------------

(defonce ^:private type-registry
  (atom #{:ir/zone :ir/service :ir/rule :ir/sandbox :ir/dynamic-rule}))

(defn register-type!
  "Registers a new object type in the IR schema."
  [type-kw]
  {:pre [(keyword? type-kw)]}
  (swap! type-registry conj type-kw)
  type-kw)

(defn registered-types
  "Set of object types registered in the IR."
  []
  @type-registry)

(defn known-type?
  "Checks whether an object type is registered."
  [type-kw]
  (contains? @type-registry type-kw))

(defn reset-type-registry!
  "Restores the type registry to the base v1 set."
  []
  (reset! type-registry #{:ir/zone :ir/service :ir/rule :ir/sandbox :ir/dynamic-rule}))

;; ---- IR specs (v1) ----------------------------------------------------

(s/def :ir/version #(= % current-version))
(s/def :policy/name (s/or :str string? :sym symbol? :kw keyword?))

;; Zones
(s/def :zone/iface (s/or :single string? :multi (s/coll-of string? :kind vector? :min-count 1)))
(s/def :zone/spec (s/keys :req-un [:zone/iface]))
(s/def :ir/zones (s/map-of keyword? :zone/spec))

;; Services
(s/def :service/proto #{:tcp :udp :icmp :all})
(s/def :service/port (s/or :single pos-int?
                           :multi (s/coll-of pos-int? :kind vector? :min-count 1)
                           :range (s/tuple pos-int? pos-int?)))
(s/def :service/spec (s/keys :req-un [:service/proto] :opt-un [:service/port]))
(s/def :ir/services (s/map-of keyword? :service/spec))

;; Static rules
(s/def :rule/action #{:allow :drop :reject})
(s/def :rule/from keyword?)
(s/def :rule/to keyword?)
(s/def :rule/service (s/or :single keyword? :multi (s/coll-of keyword? :kind vector? :min-count 1)))
(s/def :rule/spec (s/keys :req-un [:rule/action :rule/from :rule/to] :opt-un [:rule/service]))
(s/def :ir/rules (s/coll-of :rule/spec :kind vector?))

;; Dynamic containment sandbox
(s/def :sandbox/actions (s/coll-of #{:drop-ip :rate-limit} :kind set? :min-count 1))
(s/def :sandbox/default-ttl string?)
(s/def :sandbox/max-ttl string?)
(s/def :sandbox/max-active pos-int?)
(s/def :sandbox/spec (s/keys :req-un [:sandbox/actions :sandbox/default-ttl :sandbox/max-ttl :sandbox/max-active]))
(s/def :ir/sandboxes (s/map-of keyword? :sandbox/spec))

;; Events (alert ingestion, v1 NDJSON schema)
(s/def :event/ts string?)
(s/def :event/kind string?)
(s/def :event/src-ip string?)
(s/def :event/severity (s/int-in 0 11))
(s/def :event/refs (s/coll-of string? :kind vector?))
(s/def :event/spec (s/keys :req-un [:event/ts :event/kind :event/src-ip]
                           :opt-un [:event/severity :event/refs]))

;; Dynamic rules produced by AI or ingest
(s/def :dynamic/action #{:drop-ip :rate-limit})
(s/def :dynamic/ip string?)
(s/def :dynamic/ttl string?)
(s/def :dynamic/reason string?)
(s/def :dynamic/source (s/or :kw keyword? :str string?))
(s/def :dynamic/ts string?)
(s/def :dynamic/spec (s/keys :req-un [:dynamic/action :dynamic/ip :dynamic/ttl :dynamic/reason :dynamic/source :dynamic/ts]))
(s/def :ir/dynamic-rules (s/coll-of :dynamic/spec :kind vector?))

;; Root IR schema
(s/def :ir/schema
  (s/keys :req [:ir/version]
          :req-un [:policy/name :ir/zones :ir/services :ir/rules]
          :opt-un [:ir/sandboxes :ir/dynamic-rules]))

;; ---- Constructors and predicates ---------------------------------------------

(defn ir?
  "Returns true if the datum has basic IR structure."
  [x]
  (and (map? x)
       (contains? x :ir/version)
       (= (:ir/version x) current-version)))

(defn valid-ir?
  "Checks whether a structure conforms to the IR v1 schema."
  [data]
  (s/valid? :ir/schema data))

(defn explain-ir
  "Explains schema deviations of the IR, if any."
  [data]
  (s/explain-data :ir/schema data))

(defn make-ir
  "Creates a canonical IR structure validating essential fields."
  [{:keys [name zones services rules sandboxes dynamic-rules]}]
  (let [ir-data (cond-> {:ir/version current-version
                         :name       (if (keyword? name) (clojure.core/name name) (str name))
                         :zones      (or zones {})
                         :services   (or services {})
                         :rules      (vec (or rules []))}
                  sandboxes     (assoc :sandboxes sandboxes)
                  dynamic-rules (assoc :dynamic-rules (vec dynamic-rules)))]
    (when-not (valid-ir? ir-data)
      (throw (ex-info "Invalid IR structure"
                      {:explain (explain-ir ir-data)
                       :data    ir-data})))
    ir-data))
