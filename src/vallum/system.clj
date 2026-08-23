(ns vallum.system
  "Metadatos del proyecto: versión y fase actual del roadmap (M0–M5).

  La fase declarada acá es la fuente de verdad para el harness (qué checks
  aplican) y para la documentación. Se avanza junto con los hitos de
  docs/PROPOSAL.md §8.")

(def version
  "Versión actual del proyecto Vallum."
  {:name  "vallum"
   :major 0
   :minor 1
   :phase :M0})
