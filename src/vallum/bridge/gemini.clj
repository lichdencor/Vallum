(ns vallum.bridge.gemini
  "Gemini API adapter for the LLMBridge protocol.

  Uses the Gemini REST API (no SDK) via java.net.http, built into the JDK.
  API key read from constructor or VALLUM_GEMINI_KEY env var.

  Usage:
    (require '[vallum.bridge.gemini :as gemini])
    (def g (gemini/make-gemini-adapter))
    (bp/generate-proposals g manifest events send-fn)

  The send-fn is typically:
    (fn [context] (gemini/send-message g context))"
  (:require [clojure.string :as str]
            [cheshire.core :as json]
            [vallum.bridge.protocol :as bp])
  (:import [java.net.http HttpClient HttpRequest]
           [java.net URI]))

;; ---- Defaults -----------------------------------------------------------------

(def ^:private default-model "gemini-2.0-flash")
(def ^:private api-base "https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent")

;; ---- Prompt template ----------------------------------------------------------

(def ^:private prompt-template
  "You are Vallum, a firewall response agent. Propose containment actions
for security events, constrained by the current policy manifest.

POLICY MANIFEST:
%s

SECURITY EVENTS:
%s

Respond ONLY with a JSON object in this exact format:
{\"proposals\": [{\"action\": \"drop-ip\", \"ip\": \"1.2.3.4\", \"ttl\": \"30m\", \"reason\": \"explanation\"}]}

Constraints:
- Actions must be one of the sandbox's allowed actions
- IPs must match event src-ip fields
- TTL must not exceed the sandbox max-ttl (%s)
- Only propose actions for events that warrant containment
- If no action is needed, respond with: {\"proposals\": []}")

;; ---- Adapter record -----------------------------------------------------------

(defn- keywordize-actions
  "Converts action strings to keywords in proposal rule maps."
  [proposal]
  (if (sequential? proposal)
    (mapv keywordize-actions proposal)
    (update proposal :action keyword)))

(defn- parse-inner-json
  "Parses the inner JSON text from a Gemini response into a Clojure map."
  [text]
  (try
    (json/parse-string text true)
    (catch Exception _ nil)))

(defn- extract-proposals
  "Extracts proposal rule maps from a parsed response map.
   Returns nil (no action), a single rule map, or a vector of rule maps."
  [parsed]
  (let [proposals (or (get parsed :proposals)
                      (get parsed :proposal)
                      (when (map? parsed) parsed))]
    (cond
      (sequential? proposals) (when (seq proposals)
                                (keywordize-actions proposals))
      (map? proposals) (keywordize-actions proposals)
      :else nil)))

(defrecord GeminiAdapter [api-key model http-client]
  bp/LLMBridge
  (build-context [_ manifest events]
    (let [manifest-str (json/generate-string manifest {:pretty true :sort-keys true})
          events-str (json/generate-string events {:pretty true :sort-keys true})
          max-ttl (some-> manifest :sandboxes first :sandbox/max-ttl (str "max-ttl "))]
      (format prompt-template manifest-str events-str (or max-ttl "configured by sandbox"))))

  (parse-proposal [_ raw-response]
    (try
      (when (and raw-response (contains? raw-response "candidates"))
        (let [candidates (get raw-response "candidates")
              first-text (some-> candidates first (get "content") (get "parts") first (get "text"))]
          (when first-text
            (some-> first-text parse-inner-json extract-proposals))))
      (catch Exception _
        nil))))

;; ---- HTTP helpers --------------------------------------------------------------

(defn- build-request
  "Builds an HTTP POST request to the Gemini API with the given context."
  [adapter context]
  (let [model-name (or (:model adapter) default-model)
        url (format (str api-base "?key=%s") model-name (:api-key adapter))
        body (json/generate-string {:contents [{:parts [{:text context}]}]})]
    (-> (HttpRequest/newBuilder (URI. url))
        (.header "Content-Type" "application/json")
        (.POST (java.net.http.HttpRequest$BodyPublishers/ofString body))
        (.build))))

(defn send-message
  "Sends a prompt context string to the Gemini API and returns the parsed
   JSON response map. Returns nil on HTTP errors or parse failures."
  [adapter context]
  (try
    (let [client (:http-client adapter)
          request (build-request adapter context)
          response (.send client request (java.net.http.HttpResponse$BodyHandlers/ofString))]
      (if (= 200 (.statusCode response))
        (try
          (json/parse-string (.body response))
          (catch Exception _
            nil))
        nil))
    (catch Exception _
      nil)))

;; ---- Constructor ---------------------------------------------------------------

(defn make-gemini-adapter
  "Creates a Gemini adapter for the LLMBridge protocol.

   Arguments:
     api-key — Gemini API key string (or nil to use VALLUM_GEMINI_KEY env var)
     model   — Optional model name (default: gemini-2.0-flash)
     http-client — Optional HttpClient (default: HttpClient/newBuilder().build())

   Usage:
     (def g (make-gemini-adapter))                    ;; from env var VALLUM_GEMINI_KEY
     (def g (make-gemini-adapter \"your-api-key\"))     ;; explicit key
     (def g (make-gemini-adapter \"key\" \"gemini-2.0-flash\")) ;; custom model"
  ([] (make-gemini-adapter nil))
  ([api-key]
   (make-gemini-adapter api-key default-model))
  ([api-key model]
   (let [resolved-key (or api-key (System/getenv "VALLUM_GEMINI_KEY"))]
     (assert (and (string? resolved-key) (not (str/blank? resolved-key)))
             "Gemini API key required: pass it or set VALLUM_GEMINI_KEY")
     (->GeminiAdapter resolved-key model (.build (HttpClient/newBuilder)))))
  ([api-key model http-client]
   (let [resolved-key (or api-key (System/getenv "VALLUM_GEMINI_KEY"))]
     (assert (and (string? resolved-key) (not (str/blank? resolved-key)))
             "Gemini API key required: pass it or set VALLUM_GEMINI_KEY")
     (->GeminiAdapter resolved-key model http-client))))
