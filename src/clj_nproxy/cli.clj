(ns clj-nproxy.cli
  "Command line interface."
  (:require [clj-nproxy.server :as server]
            [clj-nproxy.config :as config]
            clj-nproxy.plugin.tcp
            clj-nproxy.plugin.socks5))

(set! clojure.core/*warn-on-reflection* true)

(def default-server-opts
  {:inbound {:type :proxy
             :net-opts {:type :tcp :port 1080}
             :proxy-opts {:type :socks5}}
   :outbound {:type :direct}})

(defn start-server-from-config
  "Start proxy server from config."
  [{:keys [config-name] :or {config-name "config.edn"} :as opts}]
  (let [server-opts (merge default-server-opts (config/read-edn opts config-name))]
    (run! require (:plugins server-opts))
    (server/start-server
     (merge
      (server/edn->server-opts server-opts)
      {:log-fn tap>}))))

(defn start-server
  "Start proxy server."
  [{:keys [pr-log?] :or {pr-log? true} :as opts}]
  (when pr-log?
    (add-tap prn))
  (start-server-from-config opts)
  @(promise))
