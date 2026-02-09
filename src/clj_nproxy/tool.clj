(ns clj-nproxy.tool
  (:require [clj-nproxy.server :as server]))

(defn start-server
  [opts]
  (run! require (:plugins opts))
  (add-tap prn)
  (server/start-server
   (merge
    (server/edn->server-opts opts)
    {:log-fn tap>}))
  @(promise))
