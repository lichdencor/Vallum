(ns vallum.dsl
  "Vallum declarative DSL for firewall policy definition.

  Expands macros and functions into pure data structures (AST).
  Performs no I/O and does not interact with the operating system.

  Supports both Clojure macro syntax and Lisp/EDN data structures.")

;; ---- Identifier normalization ---------------------------------------

(defn- to-keyword
  "Converts strings or symbols to normalized keywords."
  [x]
  (cond
    (keyword? x) x
    (symbol? x)  (keyword (name x))
    (string? x)  (keyword x)
    :else        x))

(defn- normalize-service-ref
  [svc]
  (cond
    (vector? svc) (mapv to-keyword svc)
    (sequential? svc) (mapv to-keyword svc)
    :else (to-keyword svc)))

;; ---- AST constructors -------------------------------------------------

(defn zone-ast
  "Builds a zone AST node."
  [id spec]
  {:type :zone
   :id   (to-keyword id)
   :spec spec})

(defn service-ast
  "Builds a service AST node."
  [id spec]
  {:type :service
   :id   (to-keyword id)
   :spec spec})

(defn rule-ast
  "Builds a traffic rule AST node."
  [action spec]
  (let [normalized-spec (cond-> spec
                          (:from spec)    (update :from to-keyword)
                          (:to spec)      (update :to to-keyword)
                          (:service spec) (update :service normalize-service-ref))]
    {:type   :rule
     :action (to-keyword action)
     :spec   normalized-spec}))

(defn sandbox-ast
  "Builds a dynamic containment sandbox AST node."
  [id spec]
  {:type :sandbox
   :id   (to-keyword id)
   :spec spec})

;; ---- High-level macros ---------------------------------------------------

(defmacro zone
  "Declares a network zone bound to one or more interfaces."
  [id spec]
  `(zone-ast '~id ~spec))

(defmacro service
  "Declares a network service (protocol and ports)."
  [id spec]
  `(service-ast '~id ~spec))

(defmacro allow
  "Declares an allowed traffic rule between zones."
  [spec]
  `(rule-ast :allow ~spec))

(defmacro deny
  "Declares a drop rule between zones."
  [spec]
  `(rule-ast :drop ~spec))

(defmacro reject
  "Declares an explicit reject rule between zones."
  [spec]
  `(rule-ast :reject ~spec))

(defmacro sandbox
  "Declares a containment sandbox with limits for dynamic AI rules."
  [id spec]
  `(sandbox-ast '~id ~spec))

(defmacro policy
  "Main macro grouping policy declarations into an AST."
  [name & body]
  `(let [decl-forms# (vector ~@body)]
     {:type         :policy
      :name         (if (string? ~name) ~name (str ~name))
      :declarations decl-forms#}))

;; ---- Parser for Lisp/EDN forms ---------------------------------------------

(defn parse-form
  "Parses an individual Lisp/EDN form into an AST node."
  [form]
  (when (seq? form)
    (let [[head & args] form
          op (to-keyword head)]
      (case op
        :zone    (let [[id spec] args] (zone-ast id spec))
        :service (let [[id spec] args] (service-ast id spec))
        :allow   (let [[spec] args] (rule-ast :allow spec))
        :deny    (let [[spec] args] (rule-ast :drop spec))
        :reject  (let [[spec] args] (rule-ast :reject spec))
        :sandbox (let [[id spec] args] (sandbox-ast id spec))
        :policy  (let [[pname & body] args]
                   {:type         :policy
                    :name         (if (string? pname) pname (str pname))
                    :declarations (mapv parse-form body)})
        nil))))

(defn parse-policy-forms
  "Parses a sequence of forms read from a policy.lisp file into an AST."
  [forms]
  (let [pform (if (and (= 1 (count forms)) (= :policy (to-keyword (first (first forms)))))
                (first forms)
                (first (filter #(and (seq? %) (= :policy (to-keyword (first %)))) forms)))]
    (if pform
      (parse-form pform)
      ;; If not wrapped in (policy ...), build an anonymous policy
      {:type         :policy
       :name         "default"
       :declarations (->> forms
                          (map parse-form)
                          (remove nil?)
                          vec)})))
