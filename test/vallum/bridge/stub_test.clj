(ns vallum.bridge.stub-test
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.string :as str]
            [vallum.bridge.protocol :as bp]
            [vallum.bridge.stub :as stub]))

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

(deftest stub-builds-context
  (testing "build-context returns a summary string"
    (let [adapter (stub/make-stub-adapter sample-manifest sample-events)
          ctx (bp/build-context adapter sample-manifest sample-events)]
      (is (string? ctx))
      (is (str/includes? ctx "edge-host"))
      (is (str/includes? ctx "ssh.bruteforce"))))

  (testing "build-context handles empty events"
    (let [adapter (stub/make-stub-adapter sample-manifest [])
          ctx (bp/build-context adapter sample-manifest [])]
      (is (string? ctx))))

  (testing "build-context handles nil events"
    (let [adapter (stub/make-stub-adapter sample-manifest nil)
          ctx (bp/build-context adapter sample-manifest nil)]
      (is (string? ctx)))))

(deftest stub-proposes-from-severe-events
  (testing "proposes drop-ip for severe events"
    (let [adapter (stub/make-stub-adapter sample-manifest sample-events)
          proposals (bp/parse-proposal adapter nil)]
      (is (vector? proposals))
      (is (some #(= :drop-ip (:action %)) proposals))))

  (testing "no proposal for low-severity events"
    (let [events [{:ts "now" :kind "scan" :src-ip "[IP]" :severity 2}]
          adapter (stub/make-stub-adapter sample-manifest events)
          proposals (bp/parse-proposal adapter nil)]
      (is (nil? proposals)))))

(deftest stub-generate-proposals
  (testing "generate-proposals chains with stub"
    (let [adapter (stub/make-stub-adapter sample-manifest sample-events)
          result (bp/generate-proposals adapter sample-manifest sample-events identity)]
      (is (or (nil? result) (vector? result) (map? result))))))

(deftest stub-canned-response
  (testing "canned response overrides heuristic"
    (let [canned [{:action :rate-limit :ip "[IP]" :ttl "5m" :reason "canned"}]
          low-sev-events [{:ts "now" :kind "scan" :src-ip "[IP]" :severity 2}]
          adapter (stub/make-stub-adapter sample-manifest low-sev-events
                                          {:canned-proposals canned})
          proposals (bp/parse-proposal adapter nil)]
      (is (= canned proposals)))))
