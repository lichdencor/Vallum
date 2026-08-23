(ns vallum.compile-test
  (:require [clojure.test :refer [deftest is testing]]
            [vallum.compile :as c]
            [vallum.dsl :as dsl]
            [vallum.ir :as ir]))

(deftest compile-ast-test
  (testing "successful AST to IR compilation"
    (let [ast (dsl/policy "edge-host"
                          (dsl/zone :wan {:iface "eth0"})
                          (dsl/zone :lan {:iface "eth1"})
                          (dsl/service :ssh {:proto :tcp :port 22})
                          (dsl/service :web {:proto :tcp :port [80 443]})
                          (dsl/allow {:from :lan :to :wan})
                          (dsl/allow {:from :wan :to :lan :service :web})
                          (dsl/sandbox :containment
                                       {:actions     #{:drop-ip :rate-limit}
                                        :default-ttl "30m"
                                        :max-ttl     "24h"
                                        :max-active  50}))
          ir (c/compile-ast ast)]
      (is (ir/valid-ir? ir))
      (is (= "edge-host" (:name ir)))
      (is (= {:iface "eth0"} (get-in ir [:zones :wan])))
      (is (= {:proto :tcp :port [80 443]} (get-in ir [:services :web])))
      (is (= 2 (count (:rules ir))))))

  (testing "determinism (I4): successive compilations produce identical IR"
    (let [ast1 (dsl/policy "p1"
                           (dsl/zone :wan {:iface "eth0"})
                           (dsl/zone :lan {:iface "eth1"})
                           (dsl/allow {:from :lan :to :wan}))
          ast2 (dsl/policy "p1"
                           (dsl/zone :lan {:iface "eth1"})
                           (dsl/zone :wan {:iface "eth0"})
                           (dsl/allow {:from :lan :to :wan}))
          ir1 (c/compile-ast ast1)
          ir2 (c/compile-ast ast2)]
      (is (= ir1 ir2))
      (is (= (pr-str ir1) (pr-str ir2)))))

  (testing "compilation errors on undeclared references"
    (is (thrown-with-msg? Exception #"Source zone not declared"
                          (c/compile-ast (dsl/policy "bad"
                                                     (dsl/zone :wan {:iface "eth0"})
                                                     (dsl/allow {:from :lan :to :wan})))))
    (is (thrown-with-msg? Exception #"Service not declared"
                          (c/compile-ast (dsl/policy "bad"
                                                     (dsl/zone :wan {:iface "eth0"})
                                                     (dsl/zone :lan {:iface "eth1"})
                                                     (dsl/allow {:from :lan :to :wan :service :dns})))))))
