(ns vallum.manifest-test
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [cheshire.core :as json]
            [vallum.ir :as ir]
            [vallum.manifest :as m]
            [vallum.compile :as c]
            [vallum.dsl :as dsl]))

(def sample-ir
  (ir/make-ir
   {:name      "edge-host"
    :zones     {:wan {:iface "eth0"}
                :lan {:iface "eth1"}}
    :services  {:ssh {:proto :tcp :port 22}
                :web {:proto :tcp :port [80 443]}}
    :rules     [{:action :allow :from :lan :to :wan}
                {:action :allow :from :wan :to :lan :service :web}]
    :sandboxes {:containment {:actions     #{:drop-ip :rate-limit}
                              :default-ttl "30m"
                              :max-ttl     "24h"
                              :max-active  50}}}))

(def sample-dynamic-rules
  [{:action :drop-ip
    :ip     "[IP_ADDRESS]"
    :ttl    "45m"
    :reason "SSH brute-force"
    :source :agent/gemini
    :ts     "2026-08-22T20:15:00Z"}])

(deftest manifest-structure
  (testing "basic manifest shape"
    (let [manifest (m/make-manifest sample-ir sample-dynamic-rules)]
      (is (= 1 (:manifest/version manifest)))
      (is (= "edge-host" (:policy/name manifest)))
      (is (= 1 (:ir/version manifest)))
      (is (map? (:zones manifest)))
      (is (map? (:services manifest)))
      (is (vector? (:rules manifest)))
      (is (vector? (:sandboxes manifest))))))

(deftest manifest-rule-conversion
  (testing "rules are converted to JSON-safe form"
    (let [manifest (m/make-manifest sample-ir sample-dynamic-rules)]
      (is (= 2 (count (:rules manifest))))
      (is (= "allow" (:action (first (:rules manifest)))))
      (is (= "lan" (:from (first (:rules manifest)))))
      (is (= "wan" (:to (first (:rules manifest)))))
      (is (= "web" (:service (second (:rules manifest))))))))

(deftest manifest-sandbox-conversion
  (testing "sandboxes with their active dynamic rules"
    (let [manifest (m/make-manifest sample-ir sample-dynamic-rules)
          sbox (first (:sandboxes manifest))]
      (is (= "containment" (:sandbox/id sbox)))
      (is (= #{"drop-ip" "rate-limit"} (set (:sandbox/actions sbox))))
      (is (= "30m" (:sandbox/default-ttl sbox)))
      (is (= "24h" (:sandbox/max-ttl sbox)))
      (is (= 50 (:sandbox/max-active sbox)))
      (is (= 1 (count (:sandbox/active-rules sbox))))
      (is (= "[IP_ADDRESS]" (:ip (first (:sandbox/active-rules sbox))))))))

(deftest manifest-no-dynamic-rules
  (testing "sandboxes without active rules omit active-rules key"
    (let [manifest (m/make-manifest sample-ir [])
          sbox (first (:sandboxes manifest))]
      (is (not (contains? sbox :sandbox/active-rules))))))

(deftest manifest-json
  (testing "JSON serialization is valid and deterministic"
    (let [manifest (m/make-manifest sample-ir sample-dynamic-rules)
          json-str (m/manifest->json manifest)]
      (is (string? json-str))
      (is (pos? (count json-str)))
      (is (str/includes? json-str "edge-host"))
      (is (str/includes? json-str "[IP_ADDRESS]"))
      (is (str/includes? json-str "manifest/version"))
      (is (= json-str (m/manifest->json manifest)))
      (let [parsed (json/parse-string json-str true)]
        (is (= "edge-host" (:policy/name parsed)))))))

(deftest manifest-from-dsl
  (testing "manifest built from DSL compilation works end-to-end"
    (let [ast (dsl/policy "edge-host"
                          (dsl/zone :wan {:iface "eth0"})
                          (dsl/zone :lan {:iface "eth1"})
                          (dsl/service :ssh {:proto :tcp :port 22})
                          (dsl/allow {:from :lan :to :wan})
                          (dsl/sandbox :containment
                                       {:actions     #{:drop-ip}
                                        :default-ttl "30m"
                                        :max-ttl     "24h"
                                        :max-active  50}))
          ir (c/compile-ast ast)
          manifest (m/make-manifest ir)]
      (is (= "edge-host" (:policy/name manifest)))
      (is (= 1 (count (:rules manifest))))
      (is (= 1 (count (:sandboxes manifest))))
      (is (= "drop-ip" (first (:sandbox/actions (first (:sandboxes manifest)))))))))
