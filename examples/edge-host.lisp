;; Política de referencia Vallum (edge-host)
(policy "edge-host"
  (zone wan {:iface "eth0"})
  (zone lan {:iface "eth1"})

  (service ssh {:proto :tcp :port 22})
  (service web {:proto :tcp :port [80 443]})

  (allow {:from :lan :to :wan})
  (allow {:from :wan :to :lan :service :web})

  ;; Sandbox de contención para reglas dinámicas de IA
  (sandbox containment
    {:actions     #{:drop-ip :rate-limit}
     :default-ttl "30m"
     :max-ttl     "24h"
     :max-active  50}))
