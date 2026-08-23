(ns vallum.architecture-test
  "Reglas de arquitectura y convenciones como tests ejecutables.

  Codifica lo declarado en docs/ARCHITECTURE.md:
  - §2: todo módulo de dominio debe estar registrado en el mapa de módulos.
  - §4: dependencias estrictamente descendentes; capas puras sin I/O ni
    fuentes de no-determinismo (I4); I/O solo en la frontera (runtime,
    ingest, cli); bridge.* jamás toca runtime.
  - Convenciones: namespaces bajo vallum. y con docstring.

  Si agregás un módulo nuevo, registralo en `tiers` y en ARCHITECTURE.md §2 —
  este test te lo va a exigir."
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]])
  (:import (java.io PushbackReader InputStreamReader FileInputStream)))

;; ---- Lectura de fuentes -----------------------------------------------------

(defn- project-file
  [^String path]
  (io/file (System/getProperty "user.dir") path))

(defn- src-files
  "Todos los .clj/.cljc bajo src/vallum/."
  []
  (->> (file-seq (project-file "src/vallum"))
       (filter #(.isFile ^java.io.File %))
       (filter #(re-matches #".+\.cljc?" (.getName ^java.io.File %)))))

(defn- read-first-form
  "Lee la primera forma del archivo (la declaración ns). ::ilegible si falla."
  [^java.io.File f]
  (try
    (with-open [in (PushbackReader. (InputStreamReader. (FileInputStream. f) "UTF-8"))]
      (binding [*read-eval* false]
        (read in)))
    (catch Exception _
      ::ilegible)))

(defn- require-symbols
  "Símbolos lib de una cláusula (:require ...), resolviendo prefix lists."
  [clause]
  (->> (rest clause)
       (mapcat
        (fn [spec]
          (cond
            (symbol? spec)    [spec]
            (sequential? spec)
            (if (and (> (count spec) 1) (not (keyword? (second spec))))
              ;; prefix list: [clojure [string :as s] [set]]
              (let [[prefix & subs] spec]
                (map (fn [sub]
                       (let [leaf (if (sequential? sub) (first sub) sub)]
                         (symbol (str prefix "." leaf))))
                     subs))
              [(first spec)])
            :else nil)))
       (remove nil?)))

(defn- ns-info
  "Extrae {:name :doc :requires} de una declaración ns. nil si no es ns."
  [form]
  (when (and (seq? form) (= 'ns (first form)))
    (let [[_ nombre & cuerpo] form
          doc (when (string? (first cuerpo)) (first cuerpo))]
      {:nombre    nombre
       :doc       doc
       :requires  (->> cuerpo
                       (filter #(and (seq? %) (= :require (first %))))
                       (mapcat require-symbols)
                       (set))})))

(defn- sources
  "[{:file :info}] de todo src/vallum/, ordenado."
  []
  (->> (src-files)
       (sort-by #(.getPath ^java.io.File %))
       (mapv (fn [f] {:file f :info (some-> (read-first-form f) ns-info)}))))

(defn- module-of
  "'vallum.emit.nft' => 'emit.nft'. nil si no está bajo vallum."
  [ns-sym]
  (let [s (str ns-sym)]
    (when (str/starts-with? s "vallum.")
      (symbol (subs s (count "vallum."))))))

;; ---- Mapa de capas (docs/ARCHITECTURE.md §2 y §4) ---------------------------

(def ^:private tiers
  "Nivel de cada módulo de dominio. Menor = más abajo en la pila.
  Solo puede requerirse hacia abajo o lateralmente dentro del mismo nivel."
  '{dsl             1
    ir              1
    compile         2
    validate        2
    emit.nft        3
    manifest        3
    audit           4
    ingest          5
    bridge.protocol 5
    bridge.gemini   6
    bridge.stub     6
    runtime         7
    cli             8})

(def ^:private infra-modules
  "Namespaces de infraestructura: fuera del grafo de capas de dominio.
  system es metadatos puros; harness es el orquestador (nivel superior)."
  '#{system harness})

(def ^:private pure-modules
  "Capas sin I/O, sin tiempo, sin azar: determinismo total (I4)."
  '#{dsl ir compile validate emit.nft manifest audit})

(def ^:private io-frontier
  "Únicos módulos autorizados a tocar el mundo exterior (§4: solo runtime
  habla con nftables/archivos/red; ingest lee el canal NDJSON curado)."
  '#{runtime ingest cli harness})

;; ---- Patrones prohibidos ----------------------------------------------------

(def ^:private io-pattern
  "(clojure\\.java\\.(io|shell|browse)|java\\.nio\\.file|java\\.io\\.(File|Reader|Writer|InputStream|OutputStream)|\\b(slurp|spit|line-seq)\\b)")

(def ^:private nondet-pattern
  "(System/(currentTimeMillis|nanoTime)|random-uuid|\\brand\\b|\\brand-nth\\b|\\brand-int\\b|random-sample)")

(defn- module-in?
  [info modules]
  (contains? modules (some-> info :nombre module-of)))

(defn- offending-files
  "Archivos cuyo texto matchea algún patrón.
  Con :include escanea solo los módulos listados (ej: capas puras);
  con :exclude escanea todo menos ellos (ej: fuera de la frontera I/O)."
  ([pattern modules] (offending-files pattern modules :exclude))
  ([pattern modules mode]
   (let [in-scope? (case mode
                     :include #(module-in? (:info %) modules)
                     :exclude (complement #(module-in? (:info %) modules)))]
     (->> (sources)
          (filter in-scope?)
          (filter (fn [{:keys [file]}]
                    (re-find (re-pattern pattern) (slurp file))))
          (mapv #(.getPath ^java.io.File (:file %)))))))

;; ---- Tests ------------------------------------------------------------------

(deftest namespaces-bajo-vallum-con-docstring
  (doseq [{:keys [file info]} (sources)]
    (testing (str file)
      (is (some? info) "el primer form debe ser (ns ...)")
      (when info
        (is (str/starts-with? (str (:nombre info)) "vallum.") "namespace fuera de vallum.*")
        (is (string? (:doc info)) "todo namespace lleva docstring")))))

;; Cada módulo de dominio debe figurar en el mapa de módulos (ARCHITECTURE.md §2).
(deftest modulos-de-dominio-registrados-en-docs
  (let [md (slurp (project-file "docs/ARCHITECTURE.md"))
        domain (->> (sources)
                    (map #(some-> % :info :nombre module-of))
                    (remove nil?)
                    (remove infra-modules)
                    (distinct))]
    (doseq [m domain]
      (is (str/includes? md (str "`" m "`"))
          (str "módulo `" m "` no está en docs/ARCHITECTURE.md §2 — registralo"))))

  (doseq [{:keys [file info]} (sources)]
    (let [m (some-> info :nombre module-of)]
      (when (and m (not (contains? infra-modules m)))
        (is (contains? tiers m)
            (str "módulo `" m "` sin nivel en el mapa de capas de este test ("
                 (.getPath ^java.io.File file) ")"))))))

;; Las capas solo conocen capas inferiores o laterales del mismo nivel (§4).
(deftest dependencias-descendentes
  (doseq [{:keys [file info]} (sources)
          :when info
          :let [mod (module-of (:nombre info))]]
    (testing (str (.getPath ^java.io.File file))
      (is (not (contains? (:requires info) 'vallum.harness))
          "nadie debajo del harness puede requerirlo")
      (doseq [req (:requires info)
              :when (str/starts-with? (str req) "vallum.")
              :let [dep (module-of req)]]
        (cond
          (contains? infra-modules dep) nil
          (contains? infra-modules mod) nil
          :else (do
                  (is (contains? tiers dep)
                      (str "requiere módulo no registrado: " dep))
                  (is (contains? tiers mod)
                      (str "módulo propio no registrado: " mod))
                  (when (and (contains? tiers dep) (contains? tiers mod))
                    (is (<= (get tiers dep) (get tiers mod))
                        (str mod " (nivel " (get tiers mod) ") no puede depender de "
                             dep " (nivel " (get tiers dep) ") — ver §4")))))))))

;; Los bridges solo emiten EDN hacia validate; jamás llaman al runtime (§4).
(deftest bridge-nunca-toca-runtime
  (doseq [{:keys [file info]} (sources)
          :when (and info (str/starts-with? (str (module-of (:nombre info))) "bridge."))]
    (is (not (contains? (:requires info) 'vallum.runtime))
        (str (.getPath ^java.io.File file) ": bridge requiere runtime — prohibido"))))

;; Pure layers: nada de I/O ni fuentes de no-determinismo (I0/I4).
(deftest capas-puras-son-deterministas
  (let [violations-io  (offending-files io-pattern pure-modules :include)
        violations-det (offending-files nondet-pattern pure-modules :include)]
    (is (empty? violations-io) (str "I/O en capa pura: " (pr-str violations-io)))
    (is (empty? violations-det) (str "no-determinismo en capa pura: " (pr-str violations-det)))))

;; Fuera de {runtime, ingest, cli, harness} no existe I/O (§4).
(deftest io-solo-en-la-frontera
  (let [violations (offending-files io-pattern io-frontier)]
    (is (empty? violations)
        (str "I/O fuera de la frontera: " (pr-str violations)))))
