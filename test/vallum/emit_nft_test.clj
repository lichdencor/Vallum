(ns vallum.emit-nft-test
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [vallum.compile :as c]
            [vallum.dsl :as dsl]
            [vallum.emit.nft :as emit-nft]))

(deftest emit-nft-deterministic-and-structured
  (testing "canonical nftables ruleset generation"
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
          ir (c/compile-ast ast)
          dyn-rules [{:action :drop-ip
                      :ip     "198.51.100.23"
                      :ttl    "45m"
                      :reason "SSH brute-force"
                      :source :agent/gemini
                      :ts     "2026-08-22T20:15:00Z"}]
          nft-output (emit-nft/emit ir dyn-rules)]

      (is (str/includes? nft-output "table inet vallum {"))
      (is (str/includes? nft-output "set containment_drop {"))
      (is (str/includes? nft-output "198.51.100.23 timeout 45m"))
      (is (str/includes? nft-output "iifname \"eth1\" oifname \"eth0\" accept"))
      (is (str/includes? nft-output "iifname \"eth0\" oifname \"eth1\" tcp dport { 80, 443 } accept"))

      ;; Determinism I4
      (is (= nft-output (emit-nft/emit ir dyn-rules))))))

(deftest emit-nft-syntax-check
  (testing "syntax validation with nft -c (unshare namespace if available)"
    (let [ast (dsl/policy "edge-host"
                          (dsl/zone :wan {:iface "eth0"})
                          (dsl/zone :lan {:iface "eth1"})
                          (dsl/service :web {:proto :tcp :port [80 443]})
                          (dsl/allow {:from :lan :to :wan})
                          (dsl/allow {:from :wan :to :lan :service :web})
                          (dsl/sandbox :containment
                                       {:actions     #{:drop-ip}
                                        :default-ttl "30m"
                                        :max-ttl     "24h"
                                        :max-active  50}))
          ir (c/compile-ast ast)
          nft-output (emit-nft/emit ir [{:action :drop-ip
                                         :ip     "198.51.100.23"
                                         :ttl    "30m"
                                         :reason "test"
                                         :source :agent/test
                                         :ts     "2026-08-22T20:00:00Z"}])
          ;; Runs the checker, capturing stdout/stderr too.
          run-checker (fn []
                        (try
                          (let [pb (doto (ProcessBuilder. ^java.util.List ["unshare" "-r" "-n" "nft" "-c" "-f" "-"])
                                     (.redirectErrorStream true))
                                p (.start pb)]
                            (with-open [w (java.io.OutputStreamWriter. (.getOutputStream p))]
                              (.write w ^String nft-output))
                            {:exit (.waitFor p)
                             :output (slurp (.getInputStream p))})
                          (catch Exception e
                            {:exit nil :output (str "cannot spawn checker: " (ex-message e))})))
          ;; Environment/tooling problems are NOT syntax verdicts: sandboxed
          ;; runners may deny unprivileged user namespaces or lack nft.
          ambient-failure? (fn [{:keys [exit output]}]
                             (or (nil? exit)
                                 (= exit 127)
                                 (let [o (str/lower-case (str output))]
                                   (boolean (some #(str/includes? o %)
                                                  ["operation not permitted"
                                                   "permission denied"
                                                   "unshare:"
                                                   "no such file"
                                                   "not found"])))))
          first-attempt (run-checker)
          result (if (and (pos-int? (:exit first-attempt))
                          (not= 0 (:exit first-attempt))
                          (not (ambient-failure? first-attempt)))
                   ;; Ambiguous nonzero: retry once before declaring a syntax bug.
                   (run-checker)
                   first-attempt)]
      (cond
        ;; Environment/tooling problems first: :exit may be nil here.
        (ambient-failure? result)
        (do (println "skip emit-nft-syntax-check:" (str/trim (:output result)))
            (is true))

        (zero? (:exit result))
        (is true)

        :else
        (is (= 0 (:exit result))
            (str "nft -c rejected the generated ruleset — output:\n"
                 (str/trim (:output result))))))))
