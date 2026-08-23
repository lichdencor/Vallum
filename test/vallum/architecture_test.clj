(ns vallum.architecture-test
  "Architecture and convention rules as executable tests.

  Encodes what docs/ARCHITECTURE.md declares:
  - §2: every domain module must be registered in the module map.
  - §4: strictly downward dependencies; pure layers without I/O nor
    non-determinism sources (I4); I/O only at the frontier (runtime,
    ingest, cli); bridge.* never touches runtime.
  - Conventions: namespaces under vallum. with a docstring.

  If you add a new module, register it in `tiers` and in ARCHITECTURE.md §2 —
  this test will demand it."
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]])
  (:import (java.io PushbackReader InputStreamReader FileInputStream)))

;; ---- Source reading -----------------------------------------------------

(defn- project-file
  [^String path]
  (io/file (System/getProperty "user.dir") path))

(defn- src-files
  "All .clj/.cljc under src/vallum/."
  []
  (->> (file-seq (project-file "src/vallum"))
       (filter #(.isFile ^java.io.File %))
       (filter #(re-matches #".+\.cljc?" (.getName ^java.io.File %)))))

(defn- read-first-form
  "Reads the first form of the file (the ns declaration). ::unreadable on failure."
  [^java.io.File f]
  (try
    (with-open [in (PushbackReader. (InputStreamReader. (FileInputStream. f) "UTF-8"))]
      (binding [*read-eval* false]
        (read in)))
    (catch Exception _
      ::unreadable)))

(defn- require-symbols
  "Lib symbols of a (:require ...) clause, resolving prefix lists."
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
  "Extracts {:name :doc :requires} from an ns declaration. nil if not an ns."
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
  "[{:file :info}] for all src/vallum/, sorted."
  []
  (->> (src-files)
       (sort-by #(.getPath ^java.io.File %))
       (mapv (fn [f] {:file f :info (some-> (read-first-form f) ns-info)}))))

(defn- module-of
  "'vallum.emit.nft' => 'emit.nft'. nil if not under vallum."
  [ns-sym]
  (let [s (str ns-sym)]
    (when (str/starts-with? s "vallum.")
      (symbol (subs s (count "vallum."))))))

;; ---- Layer map (docs/ARCHITECTURE.md §2 and §4) ---------------------------

(def ^:private tiers
  "Level of each domain module. Lower = lower in the stack.
  You may only require downward or sideways within the same level."
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
  "Infrastructure namespaces: outside the domain layer graph.
  system is pure metadata; harness is the orchestrator (top level)."
  '#{system harness})

(def ^:private pure-modules
  "Layers without I/O, without time, without randomness: full determinism (I4)."
  '#{dsl ir compile validate emit.nft manifest audit})

(def ^:private io-frontier
  "Only modules allowed to touch the outside world (§4: only runtime talks
  to nftables/state files/network; ingest reads the curated NDJSON channel)."
  '#{runtime ingest cli harness})

;; ---- Forbidden patterns ----------------------------------------------------

(def ^:private io-pattern
  "(clojure\\.java\\.(io|shell|browse)|java\\.nio\\.file|java\\.io\\.(File|Reader|Writer|InputStream|OutputStream)|\\b(slurp|spit|line-seq)\\b)")

(def ^:private nondet-pattern
  "(System/(currentTimeMillis|nanoTime)|random-uuid|\\brand\\b|\\brand-nth\\b|\\brand-int\\b|random-sample)")

(defn- module-in?
  [info modules]
  (contains? modules (some-> info :nombre module-of)))

(defn- offending-files
  "Files whose text matches any pattern.
   With :include scans only the listed modules (e.g. pure layers);
   with :exclude scans everything except them (e.g. outside the I/O frontier)."
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

(deftest namespaces-under-vallum-with-docstring
  (doseq [{:keys [file info]} (sources)]
    (testing (str file)
      (is (some? info) "the first form must be (ns ...)")
      (when info
        (is (str/starts-with? (str (:nombre info)) "vallum.") "namespace outside vallum.*")
        (is (string? (:doc info)) "every namespace carries a docstring")))))

;; Every domain module must appear in the module map (ARCHITECTURE.md §2).
(deftest domain-modules-registered-in-docs
  (let [md (slurp (project-file "docs/ARCHITECTURE.md"))
        domain (->> (sources)
                    (map #(some-> % :info :nombre module-of))
                    (remove nil?)
                    (remove infra-modules)
                    (distinct))]
    (doseq [m domain]
      (is (str/includes? md (str "`" m "`"))
          (str "module `" m "` not in docs/ARCHITECTURE.md §2 — register it"))))

  (doseq [{:keys [file info]} (sources)]
    (let [m (some-> info :nombre module-of)]
      (when (and m (not (contains? infra-modules m)))
        (is (contains? tiers m)
            (str "module `" m "` without a level in this test's layer map ("
                 (.getPath ^java.io.File file) ")"))))))

;; Layers only know lower layers or sideways within the same level (§4).
(deftest downward-dependencies
  (doseq [{:keys [file info]} (sources)
          :when info
          :let [mod (module-of (:nombre info))]]
    (testing (str (.getPath ^java.io.File file))
      (is (not (contains? (:requires info) 'vallum.harness))
          "nobody below the harness may require it")
      (doseq [req (:requires info)
              :when (str/starts-with? (str req) "vallum.")
              :let [dep (module-of req)]]
        (cond
          (contains? infra-modules dep) nil
          (contains? infra-modules mod) nil
          :else (do
                  (is (contains? tiers dep)
                      (str "requires unregistered module: " dep))
                  (is (contains? tiers mod)
                      (str "own module unregistered: " mod))
                  (when (and (contains? tiers dep) (contains? tiers mod))
                    (is (<= (get tiers dep) (get tiers mod))
                        (str mod " (level " (get tiers mod) ") cannot depend on "
                             dep " (level " (get tiers dep) ") — see §4")))))))))

;; Bridges only emit EDN towards validate; they never call runtime (§4).
(deftest bridge-never-touches-runtime
  (doseq [{:keys [file info]} (sources)
          :when (and info (str/starts-with? (str (module-of (:nombre info))) "bridge."))]
    (is (not (contains? (:requires info) 'vallum.runtime))
        (str (.getPath ^java.io.File file) ": bridge requires runtime — forbidden"))))

;; Pure layers: no I/O nor non-determinism sources (I0/I4).
(deftest pure-layers-are-deterministic
  (let [violations-io  (offending-files io-pattern pure-modules :include)
        violations-det (offending-files nondet-pattern pure-modules :include)]
    (is (empty? violations-io) (str "I/O in pure layer: " (pr-str violations-io)))
    (is (empty? violations-det) (str "non-determinism in pure layer: " (pr-str violations-det)))))

;; Outside {runtime, ingest, cli, harness} there is no I/O (§4).
(deftest io-only-at-the-frontier
  (let [violations (offending-files io-pattern io-frontier)]
    (is (empty? violations)
        (str "I/O outside the frontier: " (pr-str violations)))))
