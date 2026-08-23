(ns vallum.emit.nft
  "Firewall configuration emitter for the Linux nftables backend.

  Pure function translating the Intermediate Representation (IR) and active
  dynamic rules into canonical ruleset.nft syntax.

  Guarantees full determinism (I4): same input produces exactly the same
  configuration bytes."
  (:require [clojure.string :as str]))

;; ---- nftables primitive formatting ---------------------------------------

(defn- format-ports
  [port-spec]
  (cond
    (integer? port-spec)
    (str port-spec)

    (vector? port-spec)
    (if (= 1 (count port-spec))
      (str (first port-spec))
      (str "{ " (str/join ", " (sort port-spec)) " }"))

    :else
    (str port-spec)))

(defn- format-service-match
  [{:keys [proto port]}]
  (let [proto-str (if (= proto :all) nil (name proto))]
    (cond
      (and proto-str port)
      (str proto-str " dport " (format-ports port))

      proto-str
      proto-str

      :else
      "")))

(defn- format-rule-action
  [action]
  (case action
    :allow  "accept"
    :drop   "drop"
    :reject "reject"
    (name action)))

;; ---- Dynamic set generation -------------------------------------------

(defn- emit-dynamic-sets
  [sandboxes dynamic-rules]
  (when (seq sandboxes)
    (let [rendered (for [[sbox-id {:keys [actions]}] (sort-by key sandboxes)]
                     (let [lines (atom [])
                           sbox-name (name sbox-id)]
                       (when (contains? actions :drop-ip)
                         (let [drop-rules (filter #(= (:action %) :drop-ip) dynamic-rules)
                               set-name (str sbox-name "_drop")]
                           (swap! lines conj (str "    set " set-name " {"))
                           (swap! lines conj "        type ipv4_addr")
                           (swap! lines conj "        flags timeout")
                           (when (seq drop-rules)
                             (let [elems (->> drop-rules
                                              (sort-by :ip)
                                              (map (fn [{:keys [ip ttl]}] (str ip " timeout " ttl)))
                                              (str/join ", "))]
                               (swap! lines conj (str "        elements = { " elems " }"))))
                           (swap! lines conj "    }")))
                       (when (contains? actions :rate-limit)
                         (let [rl-rules (filter #(= (:action %) :rate-limit) dynamic-rules)
                               set-name (str sbox-name "_rate_limit")]
                           (swap! lines conj (str "    set " set-name " {"))
                           (swap! lines conj "        type ipv4_addr")
                           (swap! lines conj "        flags timeout")
                           (when (seq rl-rules)
                             (let [elems (->> rl-rules
                                              (sort-by :ip)
                                              (map (fn [{:keys [ip ttl]}] (str ip " timeout " ttl)))
                                              (str/join ", "))]
                               (swap! lines conj (str "        elements = { " elems " }"))))
                           (swap! lines conj "    }")))
                       (str/join "\n" @lines)))]
      (str/join "\n" (remove str/blank? rendered)))))

;; ---- Forward and input rules ----------------------------------------------

(defn- resolve-iface
  [zones zone-kw]
  (let [spec (get zones zone-kw)]
    (:iface spec)))

(defn- emit-rule
  [zones services {:keys [action from to service]}]
  (let [in-iface (resolve-iface zones from)
        out-iface (resolve-iface zones to)
        action-str (format-rule-action action)
        svc-spec (when service (get services service))
        match-str (when svc-spec (format-service-match svc-spec))
        parts (cond-> ["       "]
                in-iface  (conj (str "iifname \"" in-iface "\""))
                out-iface (conj (str "oifname \"" out-iface "\""))
                (and match-str (not (str/blank? match-str))) (conj match-str)
                true      (conj action-str))]
    (str/join " " parts)))

;; ---- Main emitter -------------------------------------------------------

(defn emit
  "Translates an IR structure into canonical nftables ruleset syntax."
  ([ir]
   (emit ir (:dynamic-rules ir [])))
  ([{:keys [name zones services sandboxes rules]} dynamic-rules]
   (let [policy-name (or name "unnamed")
         dyn-rules (or dynamic-rules [])
         sets-str (emit-dynamic-sets sandboxes dyn-rules)
         forward-rules (map #(emit-rule zones services %) rules)]
     (str/join
      "\n"
      (remove nil?
              [(str "# Vallum generated nftables ruleset\n# Policy: " policy-name)
               "table inet vallum {"
               (when (and sets-str (not (str/blank? sets-str)))
                 (str sets-str "\n"))
               "    chain input {"
               "        type filter hook input priority filter; policy drop;"
               "        ct state established,related accept"
               "        ct state invalid drop"
               "        iif \"lo\" accept"
               (when (some #(contains? (:actions (val %)) :drop-ip) sandboxes)
                 "        ip saddr @containment_drop drop")
               "    }"
               ""
               "    chain forward {"
               "        type filter hook forward priority filter; policy drop;"
               "        ct state established,related accept"
               "        ct state invalid drop"
               (when (some #(contains? (:actions (val %)) :drop-ip) sandboxes)
                 "        ip saddr @containment_drop drop")
               (when (some #(contains? (:actions (val %)) :rate-limit) sandboxes)
                 "        ip saddr @containment_rate_limit limit rate 10/minute accept")
               (when (seq forward-rules)
                 (str/join "\n" forward-rules))
               "    }"
               ""
               "    chain output {"
               "        type filter hook output priority filter; policy accept;"
               "    }"
               "}"])))))
