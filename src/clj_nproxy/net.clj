(ns clj-nproxy.net
  "Network abstraction."
  (:require [clj-nproxy.struct :as st])
  (:import [java.util Arrays]
           [java.io InputStream OutputStream BufferedInputStream BufferedOutputStream]
           [java.net InetSocketAddress Socket ServerSocket]
           [javax.net SocketFactory ServerSocketFactory]
           [javax.net.ssl SSLSocket SSLServerSocket SSLSocketFactory SSLServerSocketFactory SSLParameters SNIHostName]))

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
  {:socket socket
   :peer (socket->peer socket)
   :input-stream (socket->input-stream socket)
   :output-stream (socket->output-stream socket)})

(defn socket-callback
  "Convert socket to callback params, then invoke callback fn."
  [^Socket socket callback]
  (with-open [socket socket]
    (callback (socket->callback-params socket))))

(defn mk-socket
  "Make tcp socket."
  ^Socket [^String host ^long port]
  (let [^SocketFactory fac (SocketFactory/getDefault)]
    (.createSocket fac host port)))

(defn mk-ssl-socket
  "Make ssl socket."
  ^SSLSocket [^String host ^long port ssl-params]
  (let [^SSLSocketFactory fac (SSLSocketFactory/getDefault)
        ^SSLSocket socket (.createSocket fac host port)]
    (when-let [{:keys [sni alpn]} ssl-params]
      (let [^SSLParameters params (.getSSLParameters socket)]
        (when (some? sni)
          (let [sni (map #(SNIHostName. ^String %) sni)]
            (.setServerNames params (Arrays/asList (object-array sni)))))
        (when (some? alpn)
          (.setApplicationProtocols params (object-array alpn)))
        (.setSSLParameters socket params)))
    socket))

(defmethod mk-client :tcp [opts callback]
  (let [{:keys [host port ssl? ssl-params]} opts
        ^Socket socket (if ssl?
                         (mk-ssl-socket host port ssl-params)
                         (mk-socket host port))]
    (socket-callback socket callback)))

(defn mk-server-socket
  "Make tcp server socket."
  ^ServerSocket [^long port]
  (let [^ServerSocketFactory fac (ServerSocketFactory/getDefault)]
    (.createServerSocket fac port)))

(defn mk-ssl-server-socket
  "Make ssl server socket."
  ^SSLServerSocket [^long port ssl-params]
  (let [^SSLServerSocketFactory fac (SSLServerSocketFactory/getDefault)
        ^SSLServerSocket server (.createServerSocket fac port)]
    (when-let [{:keys [alpn]} ssl-params]
      (let [^SSLParameters params (.getSSLParameters server)]
        (when (some? alpn)
          (.setApplicationProtocols params (object-array alpn)))
        (.setSSLParameters server params)))
    server))

(defmethod mk-server :tcp [opts callback]
  (let [{:keys [port ssl? ssl-params]} opts
        ^ServerSocket server (if ssl?
                               (mk-ssl-server-socket port ssl-params)
                               (mk-server-socket port))]
    (Thread/startVirtualThread
     (fn []
       (with-open [server server]
         (loop []
           (let [socket (.accept server)]
             (Thread/startVirtualThread
              #(socket-callback socket callback)))
           (recur)))))
    server))
