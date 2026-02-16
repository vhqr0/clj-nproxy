(ns clj-nproxy.proxy
  "Proxy abstraction."
  (:require [clj-nproxy.struct :as st]))

(set! clojure.core/*warn-on-reflection* true)

(defmulti mk-client
  "Make client based on options, block until callback finished.
  callback: accept {:keys [input-stream output-stream]}"
  (fn [opts _server _host _port _callback] (:type opts)))

(defmulti mk-server
  "Make server based on options, block until callback finished.
  callback: accept {:keys [input-stream output-stream host port]}"
  (fn [opts _client _callback] (:type opts)))

(defmulti edn->client-opts :type)
(defmulti edn->server-opts :type)
(defmethod edn->client-opts :default [opts] opts)
(defmethod edn->server-opts :default [opts] opts)

(defn sim-conn
  "Simulate connection on internal pipe stream."
  [client-opts server-opts host port client-proc server-proc]
  (st/sim-conn
   #(mk-client client-opts % host port client-proc)
   #(mk-server server-opts % server-proc)))
