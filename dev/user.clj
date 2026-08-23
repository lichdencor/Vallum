(ns user
  "Utilidades de desarrollo, cargadas automáticamente en `clojure -M:repl`.

  El flujo típico: editar código → (refresh) → correr checks → repetir.
  Todo el feedback del proyecto vive a un llamado de distancia."
  (:require [clojure.tools.namespace.repl :refer [refresh]]
            [vallum.harness :as h]
            [vallum.system :as system]))

(defn run-tests
  "Suite completa de tests en este proceso."
  []
  (require 'vallum.run-all)
  (@(resolve 'vallum.run-all/run-suite)))

(comment
 ;; ciclo de desarrollo:
 (refresh)
 (run-tests)

 ;; feedback de calidad:
 (h/run-fast!)                 ; lint + formato + arquitectura + tests
 (h/run-checks)                ; datos crudos de todos los checks aplicables
 (h/run-one :lint/kondo)

 ;; metadatos:
 system/version)
