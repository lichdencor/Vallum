(ns vallum.ingest
  "Alert ingestion: reads a curated NDJSON event file, validates every
  event against the closed event schema, and yields validated event maps.

  Vallum does not read raw logs. It consumes a channel curated by the
  operator — whoever deploys decides which events exist and can impose
  greater restrictions externally (upstream filtering/aggregation,
  controlled enrichment) and internally via sandbox budgets.

  v1 supports a single mode: its own NDJSON file, watched by the runtime.
  Future modes (fail2ban action, journald, HTTP webhook) enter as adapters
  of the same pattern.

  Usage:
    (require '[vallum.ingest :as ingest])
    (ingest/parse-event-line \"{\\\"ts\\\":\\\"2026-08-22T20:14:59Z\\\",...}\")
    (ingest/read-events-file \"/var/log/vallum/events.ndjson\")"
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.spec.alpha :as s]
            [cheshire.core :as json]
            [vallum.ir :as ir]))

;; ---- Event parsing -----------------------------------------------------------

(defn parse-event-line
  "Parses a single NDJSON line into an event map.
  Returns {:ok <event>} on success, {:ok false :error <msg>} on failure."
  [line]
  (try
    (let [trimmed (str/trim line)]
      (if (str/blank? trimmed)
        {:ok false :error :blank-line}
        (let [parsed (json/parse-string trimmed true)]
          (if (map? parsed)
            {:ok parsed}
            {:ok false :error :not-a-map}))))
    (catch Exception e
      {:ok false :error :invalid-json :explain (.getMessage e)})))

(defn validate-event
  "Validates a parsed event map against the event schema.
  Returns nil if valid, or a map with :error and :explain."
  [event]
  (cond
    (not (map? event))
    {:error :not-a-map :explain "Event must be a map"}

    (not (s/valid? :event/spec event))
    (let [expl (s/explain-data :event/spec event)]
      {:error :invalid-event-schema :explain (pr-str expl)})

    :else nil))

(defn parse-and-validate
  "One-step parse + validate an NDJSON line.
  Returns {:ok <event>} or {:ok false :error ... :explain ...}."
  [line]
  (let [{:keys [ok] :as parse-result} (parse-event-line line)]
    (if-not ok
      (assoc parse-result :line line)
      (let [event (:ok parse-result)
            v (validate-event event)]
        (if v
          (assoc v :ok false :line line)
          {:ok event})))))

;; ---- File reading ------------------------------------------------------------

(defn read-events-file
  "Reads all lines from an NDJSON file, parses and validates each.
  Returns {:events [validated-events] :errors [{:line <n> :error ...}]}.

  Errors are non-fatal: malformed or invalid lines are collected and
  reported, never crash the process."
  [path]
  (let [result (atom {:events [] :errors []})]
    (try
      (with-open [rdr (io/reader path)]
        (doseq [[idx line] (map-indexed vector (line-seq rdr))]
          (let [res (parse-and-validate line)]
            (if (:ok res)
              (swap! result update :events conj (:ok res))
              (swap! result update :errors conj
                     (assoc res :line-number (inc idx)))))))
      (catch java.io.FileNotFoundException e
        (swap! result assoc :error (str "File not found: " (.getMessage e))))
      (catch Exception e
        (swap! result assoc :error (.getMessage e))))
    @result))
