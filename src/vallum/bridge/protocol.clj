(ns vallum.bridge.protocol
  "LLMBridge adapter protocol and shared data definitions.

  The protocol defines two methods that every adapter must implement:
  - build-context: manifests + events → prompt string for the LLM
  - parse-proposal: raw model response → candidate EDN rules

  A convenience function generate-proposals chains a send-fn between
  build-context and parse-proposal for online adapters (Gemini, etc.).

  Usage:
    (require '[vallum.bridge.protocol :as bp])
    (bp/generate-proposals adapter manifest events send-fn)")

(defprotocol LLMBridge
  "Provider-agnostic adapter for LLM-based action proposal.

  Each adapter (Gemini, stub, etc.) implements both methods.
  build-context constructs the prompt; parse-proposal interprets the
  model's response into candidate dynamic rules for the validator."
  (build-context [this manifest events]
    "Builds the prompt/context string from the policy manifest and events.
     Returns a string that will be sent to the LLM.")
  (parse-proposal [this raw-response]
    "Parses the LLM's raw response into candidate dynamic rules.
     Returns nil (no action), a single rule map, or a vector of rule maps."))

(defn generate-proposals
  "Convenience: build context, send via send-fn, then parse the response.

   The send-fn receives a context string and returns a raw response string.
   For Gemini, send-fn wraps the HTTP call to the API.
   For stub adapters, send-fn is typically a no-op or identity fn.

   Returns the result of parse-proposal: nil, a rule map, or [rules]."
  [adapter manifest events send-fn]
  (let [context (build-context adapter manifest events)
        raw-response (send-fn context)]
    (parse-proposal adapter raw-response)))
