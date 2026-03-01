(ns clj-nproxy.plugin.tcp
  "TCP net impl."
  (:require [clj-nproxy.struct :as st]
            [clj-nproxy.net :as net])
  (:import [java.util Arrays]
           [java.io InputStream OutputStream BufferedInputStream BufferedOutputStream]
           [java.nio.channels Channels SocketChannel ServerSocketChannel]
           [java.net InetAddress SocketAddress InetSocketAddress UnixDomainSocketAddress Socket ServerSocket StandardProtocolFamily]
           [javax.net SocketFactory ServerSocketFactory]
           [javax.net.ssl SSLSocket SSLServerSocket SSLSocketFactory SSLServerSocketFactory SSLParameters SNIHostName]))

(set! clojure.core/*warn-on-reflection* true)

(defn addr->peer
  "Convert socket address to peer info."
  [^SocketAddress addr]
  (cond
    (instance? InetSocketAddress addr)
    (let [^InetSocketAddress addr addr]
      {:host (.getHostString addr)
       :port (.getPort addr)})
    (instance? UnixDomainSocketAddress addr)
    (let [^UnixDomainSocketAddress addr addr]
      {:path (str addr)})))

;;; socket

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
  (let [^SocketAddress addr (.getRemoteSocketAddress socket)]
    (addr->peer addr)))

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

(defn start-server-socket
  "Start server socket."
  [^ServerSocket server callback]
  (with-open [server server]
    (loop []
      (let [socket (.accept server)]
        (Thread/startVirtualThread
         #(socket-callback socket callback)))
      (recur))))

;;; socket channel

(defn socket-channel->input-stream
  "Get socket channel input stream."
  ^InputStream [^SocketChannel sc]
  (BufferedInputStream.
   (st/input-stream-with-close-fn
    (Channels/newInputStream sc)
    #(.shutdownInput sc))))

(defn socket-channel->output-stream
  "Get socket channel output stream."
  ^OutputStream [^SocketChannel sc]
  (BufferedOutputStream.
   (st/output-stream-with-close-fn
    (Channels/newOutputStream sc)
    #(.shutdownOutput sc))))

(defn socket-channel->peer
  "Convert socket channel to peer info."
  [^SocketChannel sc]
  (let [^SocketAddress addr (.getRemoteAddress sc)]
    (addr->peer addr)))

(defn socket-channel->callback-params
  "Convert socket channel to callback params."
  [^SocketChannel sc]
  {:socket-channel sc
   :peer (socket-channel->peer sc)
   :input-stream (socket-channel->input-stream sc)
   :output-stream (socket-channel->output-stream sc)})

(defn socket-channel-callback
  "Convert socket to callback params, then invoke callback fn."
  [^SocketChannel sc callback]
  (with-open [sc sc]
    (callback (socket-channel->callback-params sc))))

(defn start-server-socket-channel
  "Start server socket channel."
  [^ServerSocketChannel server callback]
  (with-open [server server]
    (loop []
      (let [sc (.accept server)]
        (Thread/startVirtualThread
         #(socket-channel-callback sc callback))
        (recur)))))

;;; tcp

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

(defmethod net/mk-client :tcp [opts callback]
  (let [{:keys [host port ssl? ssl-params]} opts
        ^Socket socket (if ssl?
                         (mk-ssl-socket host port ssl-params)
                         (mk-socket host port))]
    (socket-callback socket callback)))

(defn mk-server-socket
  "Make tcp server socket."
  ^ServerSocket [^String host ^long port]
  (let [^ServerSocketFactory fac (ServerSocketFactory/getDefault)]
    (.createServerSocket fac port 0 (InetAddress/getByName host))))

(defn mk-ssl-server-socket
  "Make ssl server socket."
  ^SSLServerSocket [^String host ^long port ssl-params]
  (let [^SSLServerSocketFactory fac (SSLServerSocketFactory/getDefault)
        ^SSLServerSocket server (.createServerSocket fac port 0 (InetAddress/getByName host))]
    (when-let [{:keys [alpn]} ssl-params]
      (let [^SSLParameters params (.getSSLParameters server)]
        (when (some? alpn)
          (.setApplicationProtocols params (object-array alpn)))
        (.setSSLParameters server params)))
    server))

(defmethod net/mk-server :tcp [opts callback]
  (let [{:keys [host port ssl? ssl-params] :or {host "localhost"}} opts
        ^ServerSocket server (if ssl?
                               (mk-ssl-server-socket host port ssl-params)
                               (mk-server-socket host port))]
    (Thread/startVirtualThread
     #(start-server-socket server callback))
    server))

;;; unix

(defmethod net/mk-client :unix [opts callback]
  (let [{:keys [^String path]} opts
        ^SocketChannel sc (SocketChannel/open StandardProtocolFamily/UNIX)]
    (.connect sc (UnixDomainSocketAddress/of path))
    (socket-channel-callback sc callback)))

(defmethod net/mk-server :unix [opts callback]
  (let [{:keys [^String path]} opts
        ^ServerSocketChannel server (ServerSocketChannel/open StandardProtocolFamily/UNIX)]
    (.bind server (UnixDomainSocketAddress/of path))
    (Thread/startVirtualThread
     #(start-server-socket-channel server callback))
    server))
