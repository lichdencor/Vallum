(ns vallum.audit
  "Semantic audit over the firewall policy manifest.

  Detects shadowed rules, redundant rules, and other semantic issues that
  are invisible at the syntax/spec level. Pure, deterministic.

  Shadowed rule: a rule that can never be reached because an earlier rule
  matches a superset of its traffic (same zone pair, broader or equal
  service match)."
  (:require [clojure.string :as str]
            [vallum.manifest :as manifest]))

;; ---- Shadow detection --------------------------------------------------------

(defn- service-superset?
  "Returns true if the service match of rule-a is a superset of rule-b's.
  A rule without :service matches *all* services (superset of anything)."
  [rule-a rule-b]
  (let [svc-a (:service rule-a)
        svc-b (:service rule-b)]
    (or (nil? svc-a)                ;; no service = matches all
        (and (some? svc-b) (= svc-a svc-b)))))

(defn- rules-shadow-each-other
  "Returns true if rule-a (earlier) shadows rule-b (later).
  Same zone pair + service-a is a superset of service-b."
  [rule-a rule-b]
  (and (= (:from rule-a) (:from rule-b))
       (= (:to rule-a) (:to rule-b))
       (service-superset? rule-a rule-b)))

(defn find-shadowed-rules
  "Scans the rule list for shadow relationships. Returns a vector of
  findings, each describing one shadowed rule.

  Finding format:
  {:type :shadowed-rule
   :shadowed {:action A :from F :to T :service S :index J}
   :by       {:action A :from F :to T :service S :index I}
   :explain  \"rule at index J shadowed by rule at index I\"}

  Rules with no :service (match all) are labelled as '(any)'."
  [rules]
  (vec
   (for [j (range (count rules))
         i (range j)                            ;; i comes before j
         :let [rule-a (nth rules i)
               rule-b (nth rules j)]
         :when (rules-shadow-each-other rule-a rule-b)]
     {:type     :shadowed-rule
      :shadowed (assoc rule-b :index j)
      :by       (assoc rule-a :index i)
      :explain  (str "rule at index " j " is shadowed by rule at index " i
                     " (" (name (:action rule-b)) " " (name (:from rule-b))
                     " → " (name (:to rule-b))
                     (if-let [s (:service rule-b)] (str " :service " s) " (any)")
                     " shadowed by " (name (:action rule-a))
                     " " (name (:from rule-a)) " → " (name (:to rule-a))
                     (if-let [s (:service rule-a)] (str " :service " s) " (any)"))})))

;; ---- Audit runner -----------------------------------------------------------

(defn audit-manifest
  "Runs all semantic checks over a manifest (including its rules).
  Returns a flat vector of findings (may be empty)."
  [manifest-data]
  (let [rules (:rules manifest-data)]
    (find-shadowed-rules rules)))

(defn audit-ir
  "Convenience: builds a manifest from IR data and audits it."
  [ir-data]
  (-> ir-data manifest/make-manifest audit-manifest))

(comment
  ;; Quick test in REPL:
  (require '[vallum.manifest :as m])
  (require '[vallum.ir :as ir])

  (let [r1 {:action :allow :from :lan :to :wan}
        r2 {:action :allow :from :lan :to :wan :service :ssh}
        r3 {:action :drop :from :wan :to :lan :service :web}
        r4 {:action :allow :from :wan :to :lan :service :web}
        manifest (m/make-manifest (ir/make-ir {:name "test" :zones {:lan {:iface "eth0"} :wan {:iface "eth1"}}
                                               :services {:ssh {:proto :tcp :port 22} :web {:proto :tcp :port 80}}
                                               :rules [r1 r2 r3 r4]}))]
    (audit-manifest manifest))
  ;; Expect: r2 shadowed by r1, r4 shadowed by r3
  )
