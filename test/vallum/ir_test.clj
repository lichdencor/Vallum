(ns vallum.ir-test
  (:require [clojure.test :refer [deftest is testing]]
            [vallum.ir :as ir]))

(deftest ir-schema-and-version
  (testing "versioning and base types"
    (is (= 1 ir/current-version))
    (is (contains? (ir/registered-types) :ir/zone))
    (is (contains? (ir/registered-types) :ir/service))
    (is (contains? (ir/registered-types) :ir/rule))
    (is (contains? (ir/registered-types) :ir/sandbox))))

(deftest make-ir-validation
  (testing "valid IR construction"
    (let [sample {:name      "edge-host"
                  :zones     {:wan {:iface "eth0"}
                              :lan {:iface "eth1"}}
                  :services  {:ssh {:proto :tcp :port 22}
                              :web {:proto :tcp :port [80 443]}}
                  :rules     [{:action :allow :from :lan :to :wan}
                              {:action :allow :from :wan :to :lan :service :web}]
                  :sandboxes {:containment {:actions     #{:drop-ip :rate-limit}
                                            :default-ttl "30m"
                                            :max-ttl     "24h"
                                            :max-active  50}}}
          ir (ir/make-ir sample)]
      (is (= 1 (:ir/version ir)))
      (is (= "edge-host" (:name ir)))
      (is (ir/valid-ir? ir))
      (is (ir/ir? ir))))

  (testing "fails on invalid IR"
    (is (thrown? Exception
                 (ir/make-ir {:name  "invalid"
                              :zones {:wan {:no-iface "foo"}}
                              :rules []})))))
