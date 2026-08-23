(ns vallum.compile
  "Vallum deterministic compiler.

  Transforms the AST produced by the DSL into the Intermediate Representation
  (IR). Enforces determinism (I4) and validates referential coherence between
  zones, services and rules at compile time."
  (:require [vallum.dsl :as dsl]
            [vallum.ir :as ir]))

;; ---- Semantic validations and coherence ------------------------------------

(defn- validate-references!
  [zones services rules]
  (let [zone-keys (set (keys zones))
        service-keys (set (keys services))]
    (doseq [{:keys [from to service] :as rule} rules]
      (when (and from (not (contains? zone-keys from)))
        (throw (ex-info (str "Source zone not declared: " (pr-str from))
                        {:error :undeclared-zone :zone from :rule rule})))
      (when (and to (not (contains? zone-keys to)))
        (throw (ex-info (str "Destination zone not declared: " (pr-str to))
                        {:error :undeclared-zone :zone to :rule rule})))
      (when service
        (let [svcs (if (vector? service) service [service])]
          (doseq [s svcs]
            (when (not (contains? service-keys s))
              (throw (ex-info (str "Service not declared: " (pr-str s))
                              {:error :undeclared-service :service s :rule rule})))))))))

;; ---- Canonical normalization (Determinism I4) --------------------------------

(defn- normalize-rule
  [{:keys [action spec]}]
  (let [{:keys [from to service]} spec]
    (cond-> {:action action
             :from   from
             :to     to}
      service (assoc :service service))))

;; ---- Main compilation function ---------------------------------------

(defn compile-ast
  "Compiles an abstract syntax tree (AST) into the Intermediate Representation
  (IR). Guarantees canonical deterministic ordering in maps and lists."
  [{:keys [type name declarations] :as ast}]
  (when-not (= type :policy)
    (throw (ex-info "AST must have a :policy root" {:ast ast})))
  (let [grouped (group-by :type declarations)
        zones (into (sorted-map)
                    (map (fn [{:keys [id spec]}] [id spec]))
                    (get grouped :zone []))
        services (into (sorted-map)
                       (map (fn [{:keys [id spec]}] [id spec]))
                       (get grouped :service []))
        sandboxes (into (sorted-map)
                        (map (fn [{:keys [id spec]}] [id spec]))
                        (get grouped :sandbox []))
        rules (mapv normalize-rule (get grouped :rule []))]

    ;; Coherence validation
    (validate-references! zones services rules)

    ;; Typed, validated IR construction
    (ir/make-ir {:name      (or name "default")
                 :zones     zones
                 :services  services
                 :sandboxes (when (seq sandboxes) sandboxes)
                 :rules     rules})))

(defn compile-forms
  "Compiles a sequence of Lisp/EDN forms into IR."
  [forms]
  (-> forms
      dsl/parse-policy-forms
      compile-ast))
