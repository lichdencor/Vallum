(ns vallum.cli
  "Vallum main command-line interface (CLI).
  Entry point for humans and scripts: compile, validate, propose, apply,
  expire, drift, and status subcommands.
  All commands output JSON (machine-readable)."
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [cheshire.core :as json]
            [vallum.compile :as compile]
            [vallum.emit.nft :as emit-nft]
            [vallum.runtime :as rt]
            [vallum.manifest :as manifest]
            [vallum.ingest :as ingest]
            [vallum.bridge.protocol :as bp]
            [vallum.system :as system])
  (:import [java.io PushbackReader])
  (:gen-class))

;; ===== Helpers ==================================================================

(defn- read-policy-forms
  [file-path]
  (let [f (io/file file-path)]
    (when-not (.exists f)
      (throw (ex-info (str "File not found: " file-path)
                      {:error :file-not-found :path file-path})))
    (with-open [rdr (io/reader f)]
      (binding [*read-eval* false]
        (let [pbr (PushbackReader. rdr)]
          (loop [forms []]
            (let [form (read {:eof ::eof} pbr)]
              (if (= form ::eof)
                forms
                (recur (conj forms form))))))))))

(defn- read-json-file
  [file-path]
  (let [f (io/file file-path)]
    (when-not (.exists f)
      (throw (ex-info (str "File not found: " file-path)
                      {:error :file-not-found :path file-path})))
    (json/parse-string (slurp f) true)))

(defn- read-json-stdin
  []
  (json/parse-string (slurp *in*) true))

(defn- parse-flags
  "Convert [\"--key\" \"val\" \"-k\" \"v\" ...] to {\"key\" \"val\" ...}.
   Positional args not starting with - are returned as :positionals vector."
  [args]
  (loop [flags {} positionals [] args args]
    (if (empty? args)
      (assoc flags :positionals positionals)
      (let [[k v & rest] args]
        (if (str/starts-with? k "-")
          (let [key (if (str/starts-with? k "--") (subs k 2) (subs k 1))]
            (if (and (some? v) (not (str/starts-with? v "-")))
              (recur (assoc flags key v) positionals rest)
              (recur (assoc flags key true) positionals (cons v rest))))
          (recur flags (conj positionals k) rest))))))

(defn- compile-to-ir
  [policy-path]
  (-> policy-path read-policy-forms compile/compile-forms))

(defn- sandbox-config-from-ir
  [ir sandbox-id]
  (get-in ir [:sandboxes (keyword sandbox-id)]))

(defn- keywordize-rule
  "Convert string-valued action/source keys to keywords for the runtime."
  [rule]
  (-> rule
      (update :action keyword)
      (update :source (fn [v] (if (string? v) (keyword v) v)))))

(defn- load-state-or-default
  [journal-path]
  (rt/load-state (or journal-path "/var/log/vallum/journal.jsonl")))

;; ===== Compile ==================================================================

(defn cmd-compile
  "compile <policy.lisp> [-o output.nft]"
  [args]
  (let [policy-path (first args)
        flags (parse-flags (rest args))]
    (if-not policy-path
      {:exit 2 :err "Usage: vallum compile <policy.lisp> [-o output.nft]"}
      (try
        (let [ir (compile-to-ir policy-path)
              nft-text (emit-nft/emit ir)
              out-path (get flags "o")]
          (if out-path
            (do (spit out-path nft-text)
                {:exit 0 :out (str "{\"ok\":true,\"written\":\"" out-path "\"")})
            {:exit 0 :out nft-text}))
        (catch Exception e
          {:exit 1 :err (str "{\"ok\":false,\"error\":\"" (.getMessage e) "\"}")})))))

;; ===== Validate =================================================================

(defn cmd-validate
  "validate <policy.lisp>"
  [args]
  (let [policy-path (first args)]
    (if-not policy-path
      {:exit 2 :err "Usage: vallum validate <policy.lisp>"}
      (try
        (let [ir (compile-to-ir policy-path)]
          {:exit 0 :out (json/generate-string {:ok true :name (:name ir)} {:key-fn name})})
        (catch Exception e
          {:exit 1 :out (json/generate-string {:ok false :error (.getMessage e)} {:key-fn name})})))))

;; ===== Propose ==================================================================

(defn cmd-propose
  "propose <policy.lisp> <events.ndjson> [--adapter stub|gemini]"
  [args]
  (let [policy-path (first args)
        events-path (second args)
        flags (parse-flags (nthrest args 2))
        adapter-name (get flags "adapter" "stub")]
    (if (or (nil? policy-path) (nil? events-path))
      {:exit 2 :err "Usage: vallum propose <policy.lisp> <events.ndjson> [--adapter stub|gemini]"}
      (try
        (let [ir (compile-to-ir policy-path)
              events (ingest/read-events-file events-path)
              m (manifest/make-manifest ir)
              proposals (case adapter-name
                          "stub"
                          (let [stub-adapter (requiring-resolve 'vallum.bridge.stub/make-stub-adapter)]
                            (bp/generate-proposals (stub-adapter m events) m events identity))
                          "gemini"
                          (let [api-key (System/getenv "VALLUM_GEMINI_KEY")]
                            (if-not api-key
                              (throw (ex-info "VALLUM_GEMINI_KEY not set" {:error :env-missing}))
                              (let [gemini-adapter (requiring-resolve 'vallum.bridge.gemini/make-gemini-adapter)
                                    send-fn (requiring-resolve 'vallum.bridge.gemini/send-message)
                                    adapter (gemini-adapter {:api-key api-key})]
                                (bp/generate-proposals adapter m events #(send-fn adapter %)))))
                          (throw (ex-info (str "Unknown adapter: " adapter-name)
                                          {:error :unknown-adapter})))]
          {:exit 0 :out (json/generate-string
                         {:ok true :proposals (if (vector? proposals) proposals (when proposals [proposals]))}
                         {:key-fn name})})
        (catch Exception e
          {:exit 1 :out (json/generate-string {:ok false :error (.getMessage e)} {:key-fn name})})))))

;; ===== Apply ====================================================================

(defn cmd-apply
  "apply <policy.lisp> --sandbox <id> --rule <json>|-- (stdin) [--journal <path>]"
  [args]
  (let [policy-path (first args)
        flags (parse-flags (rest args))
        sandbox-id (get flags "sandbox")
        rule-src (get flags "rule")]
    (if (or (nil? policy-path) (nil? sandbox-id) (nil? rule-src))
      {:exit 2 :err "Usage: vallum apply <policy.lisp> --sandbox <id> --rule <file.json>|-- [--journal <path>]"}
      (try
        (let [ir (compile-to-ir policy-path)
              sbox-cfg (sandbox-config-from-ir ir sandbox-id)]
          (when-not sbox-cfg
            (throw (ex-info (str "Sandbox not found: " sandbox-id) {:error :sandbox-not-found})))
          (let [rule-map (keywordize-rule
                          (if (= rule-src "--")
                            (read-json-stdin)
                            (read-json-file rule-src)))
                state (load-state-or-default (get flags "journal"))
                backend (rt/->LiveNftables)
                result (rt/add-dynamic-rule! state backend rule-map
                                             (keyword sandbox-id) sbox-cfg)]
            (if (:ok result)
              {:exit 0 :out (json/generate-string (assoc result :ok true) {:key-fn name})}
              {:exit 1 :out (json/generate-string result {:key-fn name})})))
        (catch Exception e
          {:exit 1 :out (json/generate-string {:ok false :error (.getMessage e)} {:key-fn name})})))))

;; ===== Expire ===================================================================

(defn cmd-expire
  "expire [--journal <path>]"
  [args]
  (let [flags (parse-flags args)]
    (try
      (let [state (load-state-or-default (get flags "journal"))
            backend (rt/->LiveNftables)
            expired (rt/expire-due-rules! state backend)]
        {:exit 0 :out (json/generate-string {:ok true :expired (count expired)} {:key-fn name})})
      (catch Exception e
        {:exit 1 :out (json/generate-string {:ok false :error (.getMessage e)} {:key-fn name})}))))

;; ===== Drift ====================================================================

(defn cmd-drift
  "drift [--journal <path>]"
  [args]
  (let [flags (parse-flags args)]
    (try
      (let [state (load-state-or-default (get flags "journal"))
            backend (rt/->LiveNftables)
            result (rt/drift-check state backend)]
        (if result
          {:exit 1 :out (json/generate-string result {:key-fn name})}
          {:exit 0 :out (json/generate-string {:drift-detected false} {:key-fn name})}))
      (catch Exception e
        {:exit 1 :out (json/generate-string {:ok false :error (.getMessage e)} {:key-fn name})}))))

;; ===== Status ===================================================================

(defn cmd-status
  "status <policy.lisp> --sandbox <id> [--journal <path>]"
  [args]
  (let [policy-path (first args)
        flags (parse-flags (rest args))
        sandbox-id (get flags "sandbox")]
    (if (or (nil? policy-path) (nil? sandbox-id))
      {:exit 2 :err "Usage: vallum status <policy.lisp> --sandbox <id> [--journal <path>]"}
      (try
        (let [ir (compile-to-ir policy-path)
              sbox-cfg (sandbox-config-from-ir ir sandbox-id)]
          (when-not sbox-cfg
            (throw (ex-info (str "Sandbox not found: " sandbox-id) {:error :sandbox-not-found})))
          (let [state (load-state-or-default (get flags "journal"))
                budget (rt/budget-status state (keyword sandbox-id) sbox-cfg)]
            {:exit 0 :out (json/generate-string budget {:key-fn name})}))
        (catch Exception e
          {:exit 1 :out (json/generate-string {:ok false :error (.getMessage e)} {:key-fn name})})))))

;; ===== Version / Help ===========================================================

(defn cmd-version
  []
  (let [{:keys [name major minor phase]} system/version]
    {:exit 0 :out (json/generate-string
                   {:version (str name " v" major "." minor)
                    :phase (clojure.core/name phase)}
                   {:key-fn clojure.core/name})}))

(defn cmd-help
  []
  (println "Vallum — Constrained policy compiler and runtime for network remediation")
  (println)
  (println "Available commands:")
  (println "  compile  <policy.lisp> [-o ruleset.nft]    Compile policy to nftables text")
  (println "  validate <policy.lisp>                     Validate policy syntax and semantics")
  (println "  propose  <policy.lisp> <events.ndjson>     Generate containment proposals via AI bridge")
  (println "           [--adapter stub|gemini]")
  (println "  apply    <policy.lisp> --sandbox <id>      Apply a dynamic rule to nftables")
  (println "           --rule <file.json>|--")
  (println "           [--journal /var/log/vallum/journal.jsonl]")
  (println "  expire   [--journal <path>]                Remove expired dynamic rules")
  (println "  drift    [--journal <path>]                Check for nftables state drift")
  (println "  status   <policy.lisp> --sandbox <id>      Show sandbox budget status")
  (println "           [--journal <path>]")
  (println "  version                                    Show version information")
  (println "  help                                       Show this help")
  {:exit 0})

;; ===== Entry ====================================================================

(defn -main
  [& args]
  (let [[subcmd & rest-args] args
        result (case subcmd
                 "compile"  (cmd-compile rest-args)
                 "validate" (cmd-validate rest-args)
                 "propose"  (cmd-propose rest-args)
                 "apply"    (cmd-apply rest-args)
                 "expire"   (cmd-expire rest-args)
                 "drift"    (cmd-drift rest-args)
                 "status"   (cmd-status rest-args)
                 "version"  (cmd-version)
                 "help"     (cmd-help)
                 nil        (cmd-help)
                 (do (binding [*out* *err*]
                       (println (str "{\"error\":\"Unknown command: " subcmd "\"}")))
                     (cmd-help)))
        {:keys [exit out err]} result]
    (when out (println out))
    (when err (binding [*out* *err*] (println err)))
    (System/exit (or exit 0))))