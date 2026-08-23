(ns vallum.dsl-test
  (:require [clojure.test :refer [deftest is testing]]
            [vallum.dsl :as dsl :refer [policy zone service allow sandbox]]))

(deftest macro-expansion-and-ast
  (testing "DSL macro expansion into AST"
    (let [p (policy "edge-host"
                    (zone :wan {:iface "eth0"})
                    (zone :lan {:iface "eth1"})
                    (service :ssh {:proto :tcp :port 22})
                    (service :web {:proto :tcp :port [80 443]})
                    (allow {:from :lan :to :wan})
                    (allow {:from :wan :to :lan :service :web})
                    (sandbox :containment
                             {:actions     #{:drop-ip :rate-limit}
                              :default-ttl "30m"
                              :max-ttl     "24h"
                              :max-active  50}))]
      (is (= :policy (:type p)))
      (is (= "edge-host" (:name p)))
      (is (= 7 (count (:declarations p))))
      (is (= {:type :zone :id :wan :spec {:iface "eth0"}}
             (first (:declarations p)))))))

(deftest parse-policy-forms-test
  (testing "parsing Lisp forms without macros"
    (let [forms '((policy "parsed-edge"
                          (zone wan {:iface "eth0"})
                          (service ssh {:proto :tcp :port 22})
                          (allow {:from :wan :to :lan :service :ssh})
                          (deny {:from :wan :to :lan})))
          ast (dsl/parse-policy-forms forms)]
      (is (= :policy (:type ast)))
      (is (= "parsed-edge" (:name ast)))
      (is (= 4 (count (:declarations ast))))
      (is (= {:type :rule :action :drop :spec {:from :wan :to :lan}}
             (last (:declarations ast)))))))
