(ns vallum.bridge.protocol-test
  (:require [clojure.test :refer [deftest is testing]]
            [vallum.bridge.protocol :as bp]))

(deftest protocol-definitions-exist
  (testing "LLMBridge protocol is defined"
    (is (some? (find-ns 'vallum.bridge.protocol))
        "bridge.protocol namespace must load")
    (is (some? (resolve 'vallum.bridge.protocol/LLMBridge))
        "LLMBridge must be defined")
    (is (some? (resolve 'vallum.bridge.protocol/build-context))
        "build-context must be defined")
    (is (some? (resolve 'vallum.bridge.protocol/parse-proposal))
        "parse-proposal must be defined")))

(deftest generate-proposals-chains-steps
  (let [record (atom [])
        adapter (reify bp/LLMBridge
                  (build-context [_ m e]
                    (swap! record conj [:build-context m e])
                    "context-string")
                  (parse-proposal [_ raw]
                    (swap! record conj [:parse-proposal raw])
                    [{:action :drop-ip :ip "1.2.3.4"}]))
        manifest {:policy/name "test"}
        events [{:kind "ssh.bruteforce" :src-ip "1.2.3.4"}]
        result (bp/generate-proposals adapter manifest events identity)]
    (is (= [{:action :drop-ip :ip "1.2.3.4"}] result))
    (is (= [[:build-context manifest events]
            [:parse-proposal "context-string"]]
           @record))))
