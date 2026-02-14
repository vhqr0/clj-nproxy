(ns clj-nproxy.proxy
  "Proxy abstraction."
  (:require [clj-nproxy.struct :as st])
  (:import [java.io InputStream OutputStream]
           [java.net InetAddress]))

(set! clojure.core/*warn-on-reflection* true)

(defmulti mk-client
  "Make client based on options, block until callback finished.
  callback: accept {:keys [input-stream output-stream]}"
  (fn [opts _is _os _host _port _callback] (:type opts)))

(defmulti mk-server
  "Make server based on options, block until callback finished.
  callback: accept {:keys [input-stream output-stream host port]}"
  (fn [opts _is _os _callback] (:type opts)))

(defmulti edn->client-opts :type)
(defmulti edn->server-opts :type)
(defmethod edn->client-opts :default [opts] opts)
(defmethod edn->server-opts :default [opts] opts)
