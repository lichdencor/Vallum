(ns vallum.bridge.gemini-test
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.string :as str]
            [vallum.bridge.protocol :as bp]
            [vallum.bridge.gemini :as gemini]))

(def sample-manifest
  {:manifest/version 1
   :policy/name "edge-host"
   :sandboxes [{:sandbox/id "containment"
                :sandbox/actions ["drop-ip" "rate-limit"]
                :sandbox/default-ttl "30m"
                :sandbox/max-ttl "24h"
                :sandbox/max-active 5}]})

(def sample-events
  [{:ts "2026-08-22T20:14:59Z" :kind "ssh.bruteforce"
    :src-ip "[IP_ADDRESS]" :severity 7}])

(deftest gemini-builds-context
  (testing "build-context includes manifest and events"
    (let [adapter (gemini/make-gemini-adapter "test-key" "test-model")
          ctx (bp/build-context adapter sample-manifest sample-events)]
      (is (string? ctx))
      (is (str/includes? ctx "edge-host"))
      (is (str/includes? ctx "ssh.bruteforce"))
      (is (str/includes? ctx "drop-ip"))
      (is (str/includes? ctx "[IP_ADDRESS]"))))

  (testing "build-context includes constraints"
    (let [adapter (gemini/make-gemini-adapter "test-key")
          ctx (bp/build-context adapter sample-manifest sample-events)]
      (is (str/includes? ctx "max-ttl"))
      (is (str/includes? ctx "\"proposals\"")))))

(deftest gemini-parses-valid-response
  (testing "parses a valid Gemini response with proposals"
    (let [adapter (gemini/make-gemini-adapter "test-key")
          gemini-response {"candidates"
                           [{"content"
                             {"parts"
                              [{"text"
                                "{\"proposals\": [{\"action\": \"drop-ip\", \"ip\": \"[IP]\", \"ttl\": \"30m\", \"reason\": \"SSH brute-force\"}]}"}]}}]}
          result (bp/parse-proposal adapter gemini-response)]
      (is (vector? result))
      (is (= :drop-ip (:action (first result))))
      (is (= "[IP]" (:ip (first result))))))

  (testing "parses empty proposals"
    (let [adapter (gemini/make-gemini-adapter "test-key")
          gemini-response {"candidates"
                           [{"content"
                             {"parts"
                              [{"text" "{\"proposals\": []}"}]}}]}
          result (bp/parse-proposal adapter gemini-response)]
      (is (nil? result))))

  (testing "parses single proposal (not array)"
    (let [adapter (gemini/make-gemini-adapter "test-key")
          gemini-response {"candidates"
                           [{"content"
                             {"parts"
                              [{"text"
                                "{\"proposal\": {\"action\": \"drop-ip\", \"ip\": \"[IP]\", \"ttl\": \"30m\", \"reason\": \"test\"}}"}]}}]}
          result (bp/parse-proposal adapter gemini-response)]
      (is (map? result))
      (is (= :drop-ip (:action result))))))

(deftest gemini-parses-malformed-response
  (testing "nil response"
    (let [adapter (gemini/make-gemini-adapter "test-key")
          result (bp/parse-proposal adapter nil)]
      (is (nil? result))))

  (testing "missing candidates"
    (let [adapter (gemini/make-gemini-adapter "test-key")
          result (bp/parse-proposal adapter {})]
      (is (nil? result))))

  (testing "empty candidates"
    (let [adapter (gemini/make-gemini-adapter "test-key")
          result (bp/parse-proposal adapter {"candidates" []})]
      (is (nil? result))))

  (testing "unparseable JSON in text"
    (let [adapter (gemini/make-gemini-adapter "test-key")
          gemini-response {"candidates"
                           [{"content"
                             {"parts"
                              [{"text" "not json at all"}]}}]}
          result (bp/parse-proposal adapter gemini-response)]
      (is (nil? result)))))

(deftest gemini-generate-proposals-with-mock
  (testing "full chain with mocked send-fn"
    (let [adapter (gemini/make-gemini-adapter "test-key")
          mock-response {"candidates"
                         [{"content"
                           {"parts"
                            [{"text"
                              "{\"proposals\": [{\"action\": \"drop-ip\", \"ip\": \"[IP]\", \"ttl\": \"30m\", \"reason\": \"test\"}]}"}]}}]}
          send-fn (fn [_ctx] mock-response)
          result (bp/generate-proposals adapter sample-manifest sample-events send-fn)]
      (is (vector? result))
      (is (= :drop-ip (:action (first result)))))))

(deftest gemini-api-key-validation
  (testing "constructor requires a key"
    (is (thrown? AssertionError (gemini/make-gemini-adapter "")))))
