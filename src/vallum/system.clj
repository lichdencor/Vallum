(ns vallum.system
  "Project metadata: current version and roadmap phase (M0–M6).

  The phase declared here is the source of truth for the harness (which
  checks apply) and for the documentation. It advances along with the
  milestones of docs/PROPOSAL.md §8.")

(def version
  "Current version of the Vallum project."
  {:name  "vallum"
   :major 0
   :minor 2
   :phase :M6})
