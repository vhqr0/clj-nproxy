(ns clj-nproxy.tool
  (:require [clj-nproxy.server :as server]))

(def default-server-opts
  {:inbound {:type :proxy
             :net-opts {:type :tcp :port 1080}
             :proxy-opts {:type :socks5}}
   :outbound {:type :direct}})

(defn start-server
  "Start proxy server."
  [opts]
  (let [opts (merge default-server-opts opts)]
    (run! require (:plugins opts))
    (add-tap prn)
    (server/start-server
     (merge
      (server/edn->server-opts opts)
      {:log-fn tap>})))
  @(promise))
