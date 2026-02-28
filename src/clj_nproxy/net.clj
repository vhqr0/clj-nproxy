(ns clj-nproxy.net
  "Network abstraction."
  (:import [java.io InputStream OutputStream]))

(set! clojure.core/*warn-on-reflection* true)

(defmulti mk-client
  "Make client based on options, block until callback finished.
  callback: accept {:keys [input-stream output-stream]}"
  (fn [opts _callback] (:type opts)))

(defmulti mk-server
  "Make server based on options, return closeable object.
  callback: accept {:keys [input-stream output-stream]}"
  (fn [opts _callback] (:type opts)))

(defmulti edn->client-opts :type)
(defmulti edn->server-opts :type)
(defmethod edn->client-opts :default [opts] opts)
(defmethod edn->server-opts :default [opts] opts)

;;; null

(defmethod mk-client :null [_opts callback]
  (callback
   {:input-stream (InputStream/nullInputStream)
    :output-stream (OutputStream/nullOutputStream)}))
