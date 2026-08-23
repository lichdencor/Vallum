(ns vallum.bridge.stub
  "Offline stub adapter for the LLMBridge protocol.

  The stub replaces a real LLM during testing, development, and the E2E
  demo. It can produce proposals heuristically (high-severity events → drop-ip)
  or return canned proposals for deterministic test scenarios.

  Usage:
    (require '[vallum.bridge.stub :as stub])
    (def a (stub/make-stub-adapter manifest events))
    (bp/parse-proposal a nil)    ;; => [{:action :drop-ip ...}]"
  (:require [vallum.bridge.protocol :as bp]))

;; ---- Default severity threshold -----------------------------------------------

(def ^:private default-min-severity 7)

;; ---- Heuristic proposal logic -------------------------------------------------

(defn- first-sandbox
  "Returns the first sandbox config from the manifest, or nil."
  [manifest]
  (first (get manifest :sandboxes [])))

(defn- severe-events
  "Filters events at or above the minimum severity threshold."
  [events min-severity]
  (filter #(>= (get % :severity 10) min-severity) events))

(defn- events->proposals
  "Heuristically generates proposals from severe events.
   For each distinct src-ip with severity >= threshold, propose drop-ip.
   Uses the first sandbox's default-ttl."
  [events manifest]
  (when-let [sandbox (first-sandbox manifest)]
    (let [ttl (or (:sandbox/default-ttl sandbox) "30m")
          actions (set (map keyword (:sandbox/actions sandbox)))
          ips (distinct (map :src-ip (severe-events events default-min-severity)))]
      (when (seq ips)
        (vec (for [ip ips]
               {:action (if (contains? actions :drop-ip) :drop-ip (first actions))
                :ip ip
                :ttl ttl
                :reason (str "Stub: high-severity event from " ip)
                :source :agent/stub
                :ts (str (java.time.Instant/now))}))))))

;; ---- Adapter record -------------------------------------------------------------

(defrecord StubAdapter [proposals summary]
  bp/LLMBridge
  (build-context [_ _ _]
    summary)
  (parse-proposal [_ _]
    proposals))

;; ---- Constructor ---------------------------------------------------------------

(defn make-stub-adapter
  "Creates a stub adapter.

   Arguments:
     manifest  — the policy manifest (map)
     events    — validated event maps
     opts      — optional map:
                 :canned-proposals — vector of rule maps (bypasses heuristic)
                 :min-severity     — override severity threshold (default 7)

   Returns a StubAdapter record implementing LLMBridge.
   parse-proposal returns the pre-computed proposals regardless of input."
  ([manifest events]
   (make-stub-adapter manifest events {}))
  ([manifest events opts]
   (let [canned (:canned-proposals opts)
         proposals (or canned (events->proposals events manifest))
         manifest-summary (str "Policy: " (get manifest :policy/name "?")
                               " · sandboxes: " (count (get manifest :sandboxes [])))
         events-summary (str (count events) " events"
                             (when (seq events)
                               (str " (last: " (:kind (last events) "?") " from "
                                    (:src-ip (last events) "?") ")")))
         summary (str "Vallum stub · " manifest-summary " · " events-summary)]
     (->StubAdapter proposals summary))))
