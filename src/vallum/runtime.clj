(ns vallum.runtime
  "Firewall policy runtime: apply, TTL scheduler, drift detection,
  budget enforcement (I3), and audit journaling.

  The only module that talks to nftables (via NftablesBackend protocol)
  and to state/journal files. Designed so the protocol can be replaced
  for testing — see MockNftables in the test namespace.

  Usage:
    (require '[vallum.runtime :as rt])
    (def backend (rt/->LiveNftables))
    (def state (rt/init-state \"/var/lib/vallum/journal.jsonl\"))
    (rt/apply-policy! state backend \"... nftables text ...\")
    (rt/add-dynamic-rule! state backend rule :containment)
    (rt/expire-due-rules! state backend)
    (rt/drift-check state backend)"
  (:require [clojure.java.io :as io]
            [clojure.java.shell :refer [sh]]
            [clojure.string :as str]
            [cheshire.core :as json]
            [vallum.validate :as v])
  (:import [java.security MessageDigest]))

;; ---- Hashing (for drift detection I4) ---------------------------------------

(defn- sha256
  "Returns the lowercase hex SHA-256 of a string."
  [s]
  (let [md (MessageDigest/getInstance "SHA-256")]
    (.update md (.getBytes s "UTF-8"))
    (->> (.digest md)
         (map (fn [b] (format "%02x" (bit-and b 0xff))))
         (str/join))))

;; ---- NftablesBackend protocol -----------------------------------------------

(defprotocol NftablesBackend
  "Abstracts interaction with the nftables tool.
  Swap for testing (see MockNftables in runtime-test)."
  (check-syntax [this nft-text]
    "Validate a ruleset via nft -c.
    Returns {:ok true} or {:ok false :error str :exit int}.")
  (apply-ruleset! [this nft-text]
    "Apply a ruleset via nft -f (stdin).
    Returns {:ok true} or {:ok false :error str :exit int}.")
  (add-element! [this set-name ip timeout-str]
    "Add an element to a named nftables set with a timeout string.
    E.g. (add-element! backend \"containment_drop\" \"10.0.0.1\" \"45m\")")
  (delete-element! [this set-name ip]
    "Remove an element from a named nftables set.
    E.g. (delete-element! backend \"containment_drop\" \"10.0.0.1\")")
  (list-ruleset [this]
    "Returns the current live nftables ruleset as a string."))

;; ---- LiveNftables: real nftables interaction --------------------------------

(defrecord LiveNftables []
  NftablesBackend
  (check-syntax [_ nft-text]
    (let [{:keys [exit out err]} (sh "nft" "-c" :in nft-text)]
      (if (zero? exit)
        {:ok true}
        {:ok false :error (str/trim (str out err)) :exit exit})))
  (apply-ruleset! [_ nft-text]
    (let [{:keys [exit out err]} (sh "nft" "-f" :in nft-text)]
      (if (zero? exit)
        {:ok true}
        {:ok false :error (str/trim (str out err)) :exit exit})))
  (add-element! [_ set-name ip timeout-str]
    (let [cmd ["nft" "add" "element" "inet" "vallum" set-name (str "{ " ip " timeout " timeout-str " }")]
          {:keys [exit out err]} (apply sh cmd)]
      (if (zero? exit)
        {:ok true}
        {:ok false :error (str/trim (str out err)) :exit exit})))
  (delete-element! [_ set-name ip]
    (let [cmd ["nft" "delete" "element" "inet" "vallum" set-name (str "{ " ip " }")]
          {:keys [exit out err]} (apply sh cmd)]
      (if (zero? exit)
        {:ok true}
        {:ok false :error (str/trim (str out err)) :exit exit})))
  (list-ruleset [_]
    (let [{:keys [exit out err]} (sh "nft" "list" "ruleset")]
      (if (zero? exit)
        out
        (throw (ex-info "Failed to list nftables ruleset"
                        {:error (str/trim err) :exit exit}))))))

;; ---- Runtime state ----------------------------------------------------------

(defn init-state
  "Creates a fresh runtime state atom.
  Accepts an optional journal path (default: /var/log/vallum/journal.jsonl).

  State shape:
    {:active-rules  {<uuid> {:rule {...} :sandbox-id <kw> :expires-at <ms>}}
     :expected-hash <sha256-of-the-last-applied-ruleset>
     :journal-path  <string>}"
  ([] (init-state "/var/log/vallum/journal.jsonl"))
  ([journal-path]
   (atom {:active-rules  {}
          :expected-hash nil
          :journal-path  journal-path})))

;; ---- Policy apply -----------------------------------------------------------

(defn apply-policy!
  "Applies a full nftables ruleset and records its hash for drift detection.
  Returns the backend result map."
  [state-atom backend nft-text]
  (let [result (apply-ruleset! backend nft-text)]
    (when (:ok result)
      (swap! state-atom assoc :expected-hash (sha256 nft-text)))
    result))

;; ---- Dynamic rule management -------------------------------------------------

(defn- parse-ttl
  "Parses a TTL string to seconds; returns nil if invalid."
  [ttl-str]
  (v/duration->seconds ttl-str))

(declare write-journal!)

(def ^:dynamic *clock*
  "Current time in milliseconds. Bind to override for testing.
  Default: (System/currentTimeMillis)."
  (fn [] (System/currentTimeMillis)))

(defn- uuid
  "Generates a random UUID string."
  []
  (str (java.util.UUID/randomUUID)))

(defn add-dynamic-rule!
  "Validates and applies a dynamic rule to nftables with TTL tracking.
  Returns {:ok true <details>} or {:ok false :error <reason>}.

  Steps:
  1. Check budget (I3): active < max-active for sandbox
  2. Parse and validate TTL
  3. Apply to nftables via backend
  4. Record in state with expiration time
  5. Write journal entry"
  [state-atom backend rule sandbox-id sandbox-config]
  (let [{:keys [action ip ttl]} rule
        active-count (count (filter #(= (:sandbox-id (val %)) sandbox-id)
                                    (:active-rules @state-atom)))
        max-active (:max-active sandbox-config)]
    (cond
      (>= active-count max-active)
      {:ok false :error :budget-exceeded
       :explain (str "Active rules " active-count " ≥ max-active " max-active)}
      :else
      (let [ttl-secs (parse-ttl ttl)]
        (if (nil? ttl-secs)
          {:ok false :error :invalid-ttl :explain (str "Cannot parse TTL: " ttl)}
          (let [set-name (str (name sandbox-id) "_" (name action))
                result (add-element! backend set-name ip ttl)]
            (if (:ok result)
              (let [rule-id (uuid)
                    expires-at (+ (*clock*) (* ttl-secs 1000))
                    entry {:rule-id    rule-id
                           :action     action
                           :ip         ip
                           :ttl        ttl
                           :ttl-secs   ttl-secs
                           :expires-at expires-at
                           :sandbox-id sandbox-id}]
                (swap! state-atom update :active-rules assoc rule-id
                       {:rule rule :sandbox-id sandbox-id :expires-at expires-at})
                (write-journal! state-atom (assoc entry :event :rule-added))
                {:ok true :rule-id rule-id :expires-at expires-at})
              (assoc result :ok false :error :apply-failed))))))))

(defn remove-dynamic-rule!
  "Removes a dynamic rule from nftables and state.
  Returns {:ok true} or {:ok false :error ...}."
  [state-atom backend rule-id]
  (if-let [entry (get-in @state-atom [:active-rules rule-id])]
    (let [{:keys [rule sandbox-id]} entry
          set-name (str (name sandbox-id) "_" (name (:action rule)))
          result (delete-element! backend set-name (:ip rule))]
      (swap! state-atom update :active-rules dissoc rule-id)
      (write-journal! state-atom {:rule-id rule-id :event :rule-removed})
      result)
    {:ok false :error :not-found :explain (str "No active rule: " rule-id)}))

(defn expire-due-rules!
  "Removes all dynamic rules whose TTL has expired.
  Returns a seq of expired rule entries (empty seq if none)."
  [state-atom backend]
  (let [now (*clock*)
        {:keys [active-rules]} @state-atom
        due (keep (fn [[id entry]]
                    (when (<= (:expires-at entry) now)
                      [id entry]))
                  active-rules)]
    (doseq [[rule-id entry] due]
      (let [{:keys [rule sandbox-id]} entry
            set-name (str (name sandbox-id) "_" (name (:action rule)))]
        (try
          (delete-element! backend set-name (:ip rule))
          (catch Exception _)))
      (swap! state-atom update :active-rules dissoc rule-id)
      (write-journal! state-atom {:rule-id rule-id :event :rule-expired}))
    (mapv (fn [[_ entry]] entry) due)))

;; ---- Drift detection ---------------------------------------------------------

(defn drift-check
  "Compares the expected nftables ruleset hash against the live state.
  Returns nil if consistent, or a drift report map.

  The first call (when expected-hash is nil) records the current hash
  and returns nil — it's the baseline, not a drift."
  [state-atom backend]
  (let [{:keys [expected-hash]} @state-atom]
    (if (nil? expected-hash)
      (do (swap! state-atom assoc :expected-hash (sha256 (list-ruleset backend)))
          nil)
      (let [live-text (list-ruleset backend)
            live-hash (sha256 live-text)]
        (if (= live-hash expected-hash)
          nil
          {:drift-detected true
           :expected-hash  expected-hash
           :live-hash      live-hash
           :at             (*clock*)})))))

;; ---- Budget tracking ---------------------------------------------------------

(defn budget-status
  "Returns {:active N :max-active M} for a given sandbox-id.
  Max-active comes from the sandbox config."
  [state-atom sandbox-id sandbox-config]
  (let [active (count (filter #(= (:sandbox-id (val %)) sandbox-id)
                              (:active-rules @state-atom)))]
    {:active active :max-active (:max-active sandbox-config)}))

;; ---- Journal -----------------------------------------------------------------

(defn write-journal!
  "Appends a JSON entry to the journal file.
  Creates parent directories if needed.
  Silently swallows I/O errors (best-effort)."
  [state-atom entry]
  (try
    (let [path (:journal-path @state-atom)
          f (java.io.File. path)]
      (io/make-parents f)
      (spit path (str (json/generate-string (assoc entry :ts (*clock*))) "\n")
            :append true))
    (catch Exception _)))
