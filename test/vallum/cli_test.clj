(ns vallum.cli-test
  "Tests for the CLI command functions.
  Commands return {:exit N :out str :err str} data — no side effects in tests."
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [cheshire.core :as json]
            [vallum.cli :as cli]))

(def ^:private test-policy
  "examples/edge-host.lisp")

(def ^:private test-events
  "test/vallum/ingest_test.clj")

(deftest cmd-version-returns-json
  (let [{:keys [exit out err]} (cli/cmd-version)
        parsed (json/parse-string out true)]
    (is (= 0 exit))
    (is (nil? err))
    (is (some? (:version parsed)))
    (is (some? (:phase parsed)))))

(deftest cmd-help-returns-usage
  (let [{:keys [exit out err]} (cli/cmd-help)]
    (is (= 0 exit))
    (is (nil? err))))

(deftest cmd-compile-succeeds
  (let [{:keys [exit out err]} (cli/cmd-compile [test-policy])]
    (is (= 0 exit))
    (is (nil? err))
    (is (str/includes? out "table inet vallum"))))

(deftest cmd-compile-with-flag-writes-file
  (let [tmp-file (str (java.io.File/createTempFile "vallum-output" ".nft"))
        {:keys [exit err]} (cli/cmd-compile [test-policy "-o" tmp-file])]
    (is (= 0 exit))
    (is (nil? err))
    (is (.exists (java.io.File. tmp-file)))
    (is (pos? (count (slurp tmp-file))))
    (.delete (java.io.File. tmp-file))))

(deftest cmd-compile-missing-file-returns-1
  (let [{:keys [exit err]} (cli/cmd-compile ["/nonexistent.lisp"])]
    (is (= 1 exit))
    (is (some? err))))

(deftest cmd-validate-succeeds
  (let [{:keys [exit out err]} (cli/cmd-validate [test-policy])
        parsed (json/parse-string out true)]
    (is (= 0 exit))
    (is (nil? err))
    (is (:ok parsed))))

(deftest cmd-validate-bad-policy-fails
  (let [{:keys [exit out err]} (cli/cmd-validate ["/nonexistent.lisp"])
        parsed (json/parse-string out true)]
    (is (= 1 exit))
    (is (nil? err))
    (is (false? (:ok parsed)))))

(deftest cmd-validate-no-arg-returns-2
  (let [{:keys [exit err]} (cli/cmd-validate [])]
    (is (= 2 exit))
    (is (some? err))))

(deftest cmd-propose-succeeds-with-stub
  (let [{:keys [exit out err]} (cli/cmd-propose [test-policy test-events "--adapter" "stub"])
        parsed (json/parse-string out true)]
    (is (= 0 exit))
    (is (nil? err))
    (is (:ok parsed))
    (is (vector? (:proposals parsed)))))

(deftest cmd-propose-no-arg-returns-2
  (let [{:keys [exit err]} (cli/cmd-propose [])]
    (is (= 2 exit))
    (is (some? err))))

(deftest cmd-apply-no-arg-returns-2
  (let [{:keys [exit err]} (cli/cmd-apply [])]
    (is (= 2 exit))
    (is (some? err))))

(deftest cmd-expire-empty-journal-succeeds
  (let [{:keys [exit out err]} (cli/cmd-expire ["--journal" "/nonexistent/journal.jsonl"])
        parsed (json/parse-string out true)]
    (is (= 0 exit))
    (is (nil? err))
    (is (:ok parsed))
    (is (= 0 (:expired parsed)))))

(deftest cmd-status-no-arg-returns-2
  (let [{:keys [exit err]} (cli/cmd-status [])]
    (is (= 2 exit))
    (is (some? err))))

(deftest cmd-status-missing-sandbox-returns-1
  (let [{:keys [exit out err]} (cli/cmd-status [test-policy "--sandbox" "bogus"])]
    (is (= 1 exit))
    (is (nil? err))))