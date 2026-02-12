(ns clj-nproxy.net
  (:require [clj-nproxy.struct :as st])
  (:import [java.io InputStream OutputStream BufferedInputStream BufferedOutputStream]
           [java.net InetSocketAddress Socket ServerSocket]
           [javax.net SocketFactory ServerSocketFactory]
           [javax.net.ssl SSLSocketFactory SSLServerSocketFactory]))

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

;;; tcp

(defn socket->input-stream
  "Get socket input stream."
  ^InputStream [^Socket socket]
  (BufferedInputStream.
   (st/input-stream-with-close-fn
    (.getInputStream socket)
    #(.shutdownInput socket))))

(defn socket->output-stream
  "Get socket output stream."
  ^OutputStream [^Socket socket]
  (BufferedOutputStream.
   (st/output-stream-with-close-fn
    (.getOutputStream socket)
    #(.shutdownOutput socket))))

(defn socket->peer
  "Convert socket to peer info."
  [^Socket socket]
  (let [^InetSocketAddress addr (.getRemoteSocketAddress socket)]
    {:host (.getHostString addr)
     :port (.getPort addr)}))

(defn socket->callback-params
  "Convert socket to callback params."
  [^Socket socket]
  {:peer (socket->peer socket)
   :input-stream (socket->input-stream socket)
   :output-stream (socket->output-stream socket)})

(defn socket-callback
  "Convert socket to callback params, then invoke callback fn."
  [^Socket socket callback]
  (with-open [socket socket]
    (callback (socket->callback-params socket))))

(defmethod mk-client :tcp [opts callback]
  (let [{:keys [host port ssl?]} opts
        ^SocketFactory fac (if ssl?
                             (SSLSocketFactory/getDefault)
                             (SocketFactory/getDefault))
        ^Socket socket (.createSocket fac ^String host ^int port)]
    (socket-callback socket callback)))

(defmethod mk-server :tcp [opts callback]
  (let [{:keys [port ssl?]} opts
        ^ServerSocketFactory fac (if ssl?
                                   (SSLServerSocketFactory/getDefault)
                                   (ServerSocketFactory/getDefault))
        ^ServerSocket server (.createServerSocket fac port)]
    (Thread/startVirtualThread
     (fn []
       (with-open [server server]
         (loop []
           (let [socket (.accept server)]
             (Thread/startVirtualThread
              #(socket-callback socket callback)))
           (recur)))))
    server))
