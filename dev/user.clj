(ns user
  "Development utilities, automatically loaded in `clojure -M:repl`.

  The typical flow: edit code → (refresh) → run checks → repeat.
  All project feedback is one call away."
  (:require [clojure.tools.namespace.repl :refer [refresh]]
            [vallum.harness :as h]
            [vallum.system :as system]))

(defn run-tests
  "Full test suite in this process."
  []
  (require 'vallum.run-all)
  (@(resolve 'vallum.run-all/run-suite)))

(comment
 ;; development cycle:
 (refresh)
 (run-tests)

 ;; quality feedback:
 (h/run-fast!)                 ; lint + formatting + architecture + tests
 (h/run-checks)                ; raw data of all applicable checks
 (h/run-one :lint/kondo)

 ;; metadata:
 system/version)
