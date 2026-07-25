(ns clj-nproxy.cli
  "Command line interface."
  (:require [clj-nproxy.server :as server]
            [clj-nproxy.config :as config]
            clj-nproxy.tcp
            clj-nproxy.http
            clj-nproxy.socks5
            clj-nproxy.vmess))

(set! clojure.core/*warn-on-reflection* true)

(def default-server-opts
  {:inbound {:type :proxy
             :net-opts {:type :tcp :port 1080}
             :proxy-opts {:type :socks5}}
   :outbound {:type :direct}})

(defn start-server
  "Start proxy server."
  [{:keys [config-name] :or {config-name "config.edn"} :as opts}]
  (let [server-opts (merge default-server-opts (config/read-edn opts config-name))]
    (-> server-opts server/edn->server-opts server/start-server))
  @(promise))
