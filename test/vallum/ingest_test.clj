(ns vallum.ingest-test
  "Tests for the event ingestion module: NDJSON parsing, event
  validation against the closed schema, and file reading."
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [vallum.ingest :as ingest]))

;; ---- parse-event-line --------------------------------------------------------

(def ^:private valid-event-json
  "{\"ts\":\"2026-08-22T20:14:59Z\",\"kind\":\"ssh.bruteforce\",\"src-ip\":\"[IP_ADDRESS]\",\"severity\":7,\"refs\":[\"alerta#4821\"]}")

(deftest parse-valid-json-line
  (let [result (ingest/parse-event-line valid-event-json)]
    (is (:ok result))
    (is (= "2026-08-22T20:14:59Z" (:ts (:ok result))))
    (is (= "ssh.bruteforce" (:kind (:ok result))))
    (is (= "[IP_ADDRESS]" (:src-ip (:ok result))))
    (is (= 7 (:severity (:ok result))))
    (is (= ["alerta#4821"] (:refs (:ok result))))))

(deftest parse-blank-line
  (let [result (ingest/parse-event-line "  ")]
    (is (false? (:ok result)))
    (is (= :blank-line (:error result)))))

(deftest parse-invalid-json
  (let [result (ingest/parse-event-line "not json")]
    (is (false? (:ok result)))
    (is (= :invalid-json (:error result)))))

(deftest parse-not-a-map
  (let [result (ingest/parse-event-line "\"just a string\"")]
    (is (false? (:ok result)))
    (is (= :not-a-map (:error result)))))

;; ---- validate-event ----------------------------------------------------------

(deftest validate-valid-event
  (let [event {:ts "2026-08-22T20:14:59Z" :kind "ssh.bruteforce" :src-ip "[IP_ADDRESS]" :severity 7 :refs ["alerta#4821"]}
        result (ingest/validate-event event)]
    (is (nil? result))))

(deftest validate-event-missing-required-field
  (let [result (ingest/validate-event {:src-ip "[IP_ADDRESS]"})]
    (is (some? result))
    (is (= :invalid-event-schema (:error result)))))

(deftest validate-event-bad-type
  (let [result (ingest/validate-event {:ts "now" :kind "ssh.bruteforce" :src-ip "[IP_ADDRESS]" :severity "high"})]
    (is (some? result))
    (is (= :invalid-event-schema (:error result)))))

(deftest validate-event-nil
  (let [result (ingest/validate-event nil)]
    (is (= :not-a-map (:error result)))))

;; ---- parse-and-validate ------------------------------------------------------

(deftest parse-and-validate-valid-line
  (let [result (ingest/parse-and-validate valid-event-json)]
    (is (:ok result))
    (is (= "ssh.bruteforce" (:kind (:ok result))))))

(deftest parse-and-validate-captures-line-on-failure
  (let [result (ingest/parse-and-validate "not json")]
    (is (false? (:ok result)))
    (is (some? (:line result)))))

;; ---- read-events-file --------------------------------------------------------

(deftest read-events-file-valid
  (let [tmp (java.io.File/createTempFile "vallum-events" ".ndjson")
        _ (spit tmp (str valid-event-json "\n" valid-event-json "\n"))
        result (ingest/read-events-file (.getAbsolutePath tmp))]
    (is (= 2 (count (:events result))))
    (is (empty? (:errors result)))
    (is (nil? (:error result)))
    (.delete tmp)))

(deftest read-events-file-with-errors
  (let [tmp (java.io.File/createTempFile "vallum-events" ".ndjson")
        _ (spit tmp (str valid-event-json "\nbad-line\n" valid-event-json "\n"))
        result (ingest/read-events-file (.getAbsolutePath tmp))]
    (is (= 2 (count (:events result))))
    (is (= 1 (count (:errors result))))
    (is (= :invalid-json (:error (first (:errors result)))))
    (is (= 2 (:line-number (first (:errors result)))))
    (.delete tmp)))

(deftest read-events-file-not-found
  (let [result (ingest/read-events-file "/nonexistent/path.ndjson")]
    (is (empty? (:events result)))
    (is (some? (:error result)))
    (is (str/starts-with? (:error result) "File not found"))))

(deftest read-events-file-empty
  (let [tmp (java.io.File/createTempFile "vallum-events" ".ndjson")
        _ (spit tmp "")
        result (ingest/read-events-file (.getAbsolutePath tmp))]
    (is (empty? (:events result)))
    (is (empty? (:errors result)))
    (.delete tmp)))
