(ns clj-nproxy.tool
  (:require [clj-nproxy.server :as server]
            [clj-nproxy.tool.core :as core]))

(def default-server-opts
  {:inbound {:type :proxy
             :net-opts {:type :tcp :port 1080}
             :proxy-opts {:type :socks5}}
   :outbound {:type :direct}})

(defn start-server
  "Start proxy server."
  [{:keys [config-name] :or {config-name "config.edn"} :as opts}]
  (let [server-opts (merge default-server-opts (core/read-edn opts config-name))]
    (run! require (:plugins server-opts))
    (add-tap prn)
    (server/start-server
     (merge
      (server/edn->server-opts server-opts)
      {:log-fn tap>})))
  @(promise))
