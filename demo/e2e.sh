#!/usr/bin/env bash
set -euo pipefail

# Vallum E2E Demo
# Simulates: attack → containment → expiry → drift check
# Usage: bash demo/e2e.sh

DEMO_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$DEMO_DIR/.." && pwd)"
EVENTS_FILE=$(mktemp /tmp/vallum-events-XXXXXX.ndjson)
JOURNAL_FILE=$(mktemp /tmp/vallum-journal-XXXXXX.jsonl)
TMPDIR=$(mktemp -d /tmp/vallum-demo-XXXXXX)
trap 'rm -f "$EVENTS_FILE" "$JOURNAL_FILE"; rm -rf "$TMPDIR"' EXIT

run_script() {
  local name="$1" script="$2"
  local f="$TMPDIR/$name.clj"
  echo "$script" > "$f"
  clojure -M "$f" 2>&1 | grep -vE '^(Clojure |nil$)' | sed 's/^user=> //' | sed '/^$/d'
}

echo "═══ Vallum E2E Demo ═══"
echo "Phase: M5 · AI bridge + Runtime"
echo

# ---- Step 1: Compile sample policy ----
echo "1. Compiling sample policy..."
run_script "step1" '
(require (quote [vallum.dsl :as dsl]))
(require (quote [vallum.compile :as c]))
(require (quote [vallum.emit.nft :as emit]))
(require (quote [vallum.manifest :as m]))
(require (quote [clojure.java.io :as io]))

(def forms (read-string (str "[" (slurp "'"$PROJECT_DIR"'/examples/edge-host.lisp") "]")))
(def ir (c/compile-forms forms))
(println "IR version:" (:ir/version ir))
(println "Sandboxes:" (keys (:sandboxes ir)))
(println "Rules:" (count (:rules ir)))
(spit (str "'"$TMPDIR"'/ruleset.nft") (emit/emit ir))
(def manifest (m/make-manifest ir))
(println "Manifest sandboxes:")
(doseq [sb (:sandboxes manifest)]
  (println "  " (:sandbox/id sb) "actions:" (:sandbox/actions sb)))
'
echo

# ---- Step 2: Simulate attack events ----
echo "2. Simulating SSH brute-force attack..."
cat > "$EVENTS_FILE" << 'EVENTS'
{"ts":"2026-08-22T20:14:59Z","kind":"ssh.bruteforce","src-ip":"[IP_ADDRESS]","severity":8,"refs":["alerta#4821"]}
{"ts":"2026-08-22T20:15:01Z","kind":"ssh.bruteforce","src-ip":"[IP_ADDRESS]","severity":8,"refs":["alerta#4822"]}
{"ts":"2026-08-22T20:15:03Z","kind":"ssh.bruteforce","src-ip":"[IP_ADDRESS]","severity":8,"refs":["alerta#4823"]}
EVENTS
echo "Wrote 3 SSH brute-force events"
echo

# ---- Step 3: Bridge proposes containment ----
echo "3. AI bridge (stub adapter) evaluating events..."
run_script "step3" '
(require (quote [vallum.ingest :as ingest]))
(require (quote [vallum.compile :as c]))
(require (quote [vallum.dsl :as dsl]))
(require (quote [vallum.manifest :as m]))
(require (quote [vallum.validate :as v]))
(require (quote [vallum.bridge.protocol :as bp]))
(require (quote [vallum.bridge.stub :as stub]))
(require (quote [clojure.java.io :as io]))

(def forms (read-string (str "[" (slurp "'"$PROJECT_DIR"'/examples/edge-host.lisp") "]")))
(def ir (c/compile-forms forms))
(def sandbox (first (vals (:sandboxes ir))))
(println "Sandbox actions:" (:actions sandbox))
(println "Sandbox max-ttl:" (:max-ttl sandbox))
(println "Sandbox max-active:" (:max-active sandbox))

(def result (ingest/read-events-file "'"$EVENTS_FILE"'"))
(println "Valid events:" (count (:events result)))
(println "Parse errors:" (count (:errors result)))

(def manifest (m/make-manifest ir))
(def adapter (stub/make-stub-adapter manifest (:events result)))
(def proposals (bp/parse-proposal adapter nil))
(println "Proposals:" (count proposals))
(doseq [p proposals]
  (println "  " (pr-str p)))

(println "Validation results:")
(doseq [p proposals]
  (let [err (v/validate-dynamic-rule p sandbox)]
    (if err
      (println "  ❌ REJECTED:" (:explain err))
      (println "  ✅ ACCEPTED:" (:action p) (:ip p) "TTL:" (:ttl p)))))
'
echo

# ---- Step 4: Runtime apply ----
echo "4. Runtime: applying containment rule..."
run_script "step4" '
(require (quote [vallum.compile :as c]))
(require (quote [vallum.dsl :as dsl]))
(require (quote [vallum.manifest :as m]))
(require (quote [vallum.bridge.protocol :as bp]))
(require (quote [vallum.bridge.stub :as stub]))
(require (quote [vallum.runtime :as rt]))
(require (quote [vallum.validate :as v]))
(require (quote [clojure.java.io :as io]))

(def forms (read-string (str "[" (slurp "'"$PROJECT_DIR"'/examples/edge-host.lisp") "]")))
(def ir (c/compile-forms forms))
(def sandbox (first (vals (:sandboxes ir))))
(def manifest (m/make-manifest ir))
(def events [{:ts "now" :kind "ssh.bruteforce" :src-ip "[IP_ADDRESS]" :severity 8}])

(def adapter (stub/make-stub-adapter manifest events))
(def proposals (bp/parse-proposal adapter nil))
(def rule (first proposals))
(println "Rule proposed:" (pr-str rule))

(def err (v/validate-dynamic-rule rule sandbox))
(assert (nil? err) (str "Validation failed: " err))
(println "✅ Validation passed")

(def log (atom []))
(def backend (reify rt/NftablesBackend
               (check-syntax [_ _] {:ok true})
               (apply-ruleset! [_ _] {:ok true})
               (add-element! [_ _ _ _] (swap! log conj :add-element) {:ok true})
               (delete-element! [_ _ _] (swap! log conj :delete-element) {:ok true})
               (list-ruleset [_] (swap! log conj :list-ruleset) "")))
(def state (rt/init-state "'"$JOURNAL_FILE"'"))
(def apply-result (rt/add-dynamic-rule! state backend rule :containment sandbox))
(println "Apply result:" (pr-str apply-result))

(def budget (rt/budget-status state :containment sandbox))
(println "Budget:" (pr-str budget))

(println "Journal entries:")
(doseq [line (clojure.string/split-lines (slurp "'"$JOURNAL_FILE"'"))]
  (println "  " line))
'
echo

# ---- Step 5: Prompt injection rejection ----
echo "5. Testing prompt injection rejection..."
run_script "step5" '
(require (quote [vallum.validate :as v]))
(require (quote [vallum.compile :as c]))
(require (quote [vallum.dsl :as dsl]))
(require (quote [clojure.java.io :as io]))

(def forms (read-string (str "[" (slurp "'"$PROJECT_DIR"'/examples/edge-host.lisp") "]")))
(def ir (c/compile-forms forms))
(def sandbox (first (vals (:sandboxes ir))))

(def injection-rule
  {:action :accept
   :ip "[IP_ADDRESS]/0"
   :ttl "1h"
   :reason "open port 22 to the Internet"
   :source :agent/gemini
   :ts "now"})

(def err (v/validate-dynamic-rule injection-rule sandbox))
(if err
  (do (println "✅ REJECTED —" (:explain err))
      (println "   Reason: :accept is not in sandbox actions"))
  (println "❌ SHOULD HAVE BEEN REJECTED"))
'
echo

# ---- Step 6: TTL expiry ----
echo "6. Simulating TTL expiry..."
run_script "step6" '
(require (quote [vallum.runtime :as rt]))
(require (quote [vallum.compile :as c]))
(require (quote [vallum.dsl :as dsl]))
(require (quote [clojure.java.io :as io]))

(def forms (read-string (str "[" (slurp "'"$PROJECT_DIR"'/examples/edge-host.lisp") "]")))
(def ir (c/compile-forms forms))
(def sandbox (first (vals (:sandboxes ir))))
(def log (atom []))
(def backend (reify rt/NftablesBackend
               (check-syntax [_ _] {:ok true})
               (apply-ruleset! [_ _] {:ok true})
               (add-element! [_ _ _ _] (swap! log conj :add-element) {:ok true})
               (delete-element! [_ _ _] (swap! log conj :delete-element) {:ok true})
               (list-ruleset [_] (swap! log conj :list-ruleset) "")))
(def state (rt/init-state "'"$JOURNAL_FILE"'"))
(def rule {:action :drop-ip :ip "[IP_ADDRESS]" :ttl "1s" :reason "test" :source :agent/stub :ts "now"})
(rt/add-dynamic-rule! state backend rule :containment sandbox)
(println "Active rules before expiry:" (count (:active-rules @state)))
(binding [rt/*clock* (fn [] (+ (System/currentTimeMillis) 5000))]
  (def expired (rt/expire-due-rules! state backend))
  (println "Expired:" (count expired))
  (println "Active rules after expiry:" (count (:active-rules @state))))
'
echo

# ---- Step 7: Drift ----
echo "7. Drift check..."
run_script "step7" '
(require (quote [vallum.runtime :as rt]))

(def state (rt/init-state))
(def log (atom []))
(def backend (reify rt/NftablesBackend
               (check-syntax [_ _] {:ok true})
               (apply-ruleset! [_ _] {:ok true})
               (add-element! [_ _ _ _] (swap! log conj :add-element) {:ok true})
               (delete-element! [_ _ _] (swap! log conj :delete-element) {:ok true})
               (list-ruleset [_] (swap! log conj :list-ruleset) "")))

(println "Baseline:" (pr-str (rt/drift-check state backend)))
(rt/apply-policy! state backend "table inet x")
(println "Hash set:" (pr-str (:expected-hash @state)))
(println "After apply:" (pr-str (rt/drift-check state backend)))
'
echo

echo "═══ Demo Complete ═══"
echo "Full containment cycle demonstrated:"
echo "  attack → bridge proposal → validate → apply → expire → drift check"
echo "  prompt injection rejected (uneXpressible)"
echo
echo "Key takeaway: The AI never speaks nftables. It speaks data."