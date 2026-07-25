(ns clj-nproxy.net
  "Network abstraction."
  (:import [java.io InputStream OutputStream]))

(set! clojure.core/*warn-on-reflection* true)

(defmulti mk-net-client
  "Make net client based on options, block until callback finished.
  callback: accept {:keys [input-stream output-stream]}"
  (fn [opts _callback] (:type opts)))

(defmulti mk-net-server
  "Make net server based on options, return closeable object.
  callback: accept {:keys [input-stream output-stream]}"
  (fn [opts _callback] (:type opts)))

(defmulti mk-wrap-client
  "Make wrap client based on options, block until callback finished.
  callback: accept {:keys [input-stream output-stream]}"
  (fn [_server opts _callback] (:type opts)))

(defmulti mk-wrap-server
  "Make wrap server based on options, block until callback finished.
  callback: accept {:keys [input-stream output-stream]}"
  (fn [_client opts _callback] (:type opts)))

(defmulti mk-proxy-client
  "Make proxy client based on options, block until callback finished.
  callback: accept {:keys [input-stream output-stream]}"
  (fn [_server opts _host _port _callback] (:type opts)))

(defmulti mk-proxy-server
  "Make proxy server based on options, block until callback finished.
  callback: accept {:keys [input-stream output-stream host port]}"
  (fn [_client opts _callback] (:type opts)))

(defmulti edn->net-client-opts :type)
(defmulti edn->net-server-opts :type)
(defmethod edn->net-client-opts :default [opts] opts)
(defmethod edn->net-server-opts :default [opts] opts)

(defmulti edn->wrap-client-opts :type)
(defmulti edn->wrap-server-opts :type)
(defmethod edn->wrap-client-opts :default [opts] opts)
(defmethod edn->wrap-server-opts :default [opts] opts)

(defmulti edn->proxy-client-opts :type)
(defmulti edn->proxy-server-opts :type)
(defmethod edn->proxy-client-opts :default [opts] opts)
(defmethod edn->proxy-server-opts :default [opts] opts)

;;; wrap

(defmethod mk-net-client :wrap [{:keys [net-opts wrap-opts]} callback]
  (mk-net-client
   net-opts
   (fn [server]
     (mk-wrap-client server wrap-opts callback))))

(defmethod mk-net-server :wrap [{:keys [net-opts wrap-opts]} callback]
  (mk-net-server
   net-opts
   (fn [client]
     (mk-wrap-server client wrap-opts callback))))

(defmethod edn->net-client-opts :wrap [opts]
  (-> opts
      (update :net-opts edn->net-client-opts)
      (update :wrap-opts edn->wrap-client-opts)))

(defmethod edn->net-server-opts :wrap [opts]
  (-> opts
      (update :net-opts edn->net-server-opts)
      (update :wrap-opts edn->wrap-server-opts)))

;;; null

(defmethod mk-net-client :null [_opts callback]
  (callback
   {:input-stream (InputStream/nullInputStream)
    :output-stream (OutputStream/nullOutputStream)}))
