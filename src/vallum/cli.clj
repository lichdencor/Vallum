(ns vallum.cli
  "Vallum main command-line interface (CLI).

  Entry point for humans and scripts: compile, validate and firewall
  administration subcommands."
  (:require [clojure.java.io :as io]
            [vallum.compile :as compile]
            [vallum.emit.nft :as emit-nft]
            [vallum.system :as system])
  (:gen-class))

(defn- read-policy-forms
  "Reads all forms from a policy file."
  [file-path]
  (let [f (io/file file-path)]
    (when-not (.exists f)
      (throw (ex-info (str "File not found: " file-path)
                      {:error :file-not-found :path file-path})))
    (with-open [in (java.io.PushbackReader. (io/reader f))]
      (binding [*read-eval* false]
        (loop [forms []]
          (let [form (read {:eof ::eof} in)]
            (if (= form ::eof)
              forms
              (recur (conj forms form)))))))))

(defn- cmd-compile
  "compile subcommand: policy -> ruleset.nft."
  [[policy-path & flags]]
  (if-not policy-path
    (do
      (println "Usage: vallum compile <policy-file.lisp> [-o output.nft]")
      (System/exit 1))
    (try
      (let [forms (read-policy-forms policy-path)
            ir (compile/compile-forms forms)
            nft (emit-nft/emit ir)
            out-idx (.indexOf ^java.util.List (vec flags) "-o")
            out-path (when (and (>= out-idx 0) (< (inc out-idx) (count flags)))
                       (nth flags (inc out-idx)))]
        (if out-path
          (do
            (spit out-path nft)
            (println (str "✓ Ruleset written to " out-path)))
          (println nft))
        (System/exit 0))
      (catch Exception e
        (binding [*out* *err*]
          (println "Compilation error:" (.getMessage e)))
        (System/exit 1)))))

(defn- cmd-version
  []
  (let [{:keys [name major minor phase]} system/version]
    (println (format "%s v%d.%d (phase %s)" name major minor (clojure.core/name phase)))
    (System/exit 0)))

(defn- cmd-help
  []
  (println "Vallum — Constrained policy compiler for network remediation")
  (println "")
  (println "Available commands:")
  (println "  compile <policy.lisp> [-o ruleset.nft]   Compiles policy to nftables")
  (println "  version                                  Shows version and active phase")
  (println "  help                                     Shows this help")
  (System/exit 0))

(defn -main
  "Main CLI entry point."
  [& args]
  (let [[subcmd & rest-args] args]
    (case subcmd
      "compile" (cmd-compile rest-args)
      "version" (cmd-version)
      "help"    (cmd-help)
      nil       (cmd-help)
      (do
        (binding [*out* *err*]
          (println (str "Unknown command: " subcmd)))
        (cmd-help)))))
