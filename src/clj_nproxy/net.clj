(ns clj-nproxy.net
  (:require [clj-nproxy.struct :as st])
  (:import [java.io InputStream OutputStream BufferedInputStream BufferedOutputStream]
           [java.net InetAddress Socket ServerSocket]
           [javax.net SocketFactory ServerSocketFactory]
           [javax.net.ssl SSLSocketFactory SSLServerSocketFactory]))

(set! clojure.core/*warn-on-reflection* true)

(defmulti mk-client
  "Make client connection based on options."
  (fn [opts _callback] (:type opts)))

(defmulti mk-server
  "Make server based on options."
  (fn [opts _callback] (:type opts)))

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

(defmethod mk-client :tcp [opts callback]
  (let [{:keys [host port ssl?]} opts
        ^SocketFactory fac (if ssl?
                             (SSLSocketFactory/getDefault)
                             (SocketFactory/getDefault))]
    (with-open [socket (.createSocket fac ^String host ^int port)]
      (callback
       (socket->input-stream socket)
       (socket->output-stream socket)))))

(defmethod mk-server :tcp [opts callback]
  (let [{:keys [host port backlog ssl?] :or {host "localhost" backlog 0}} opts
        ^ServerSocketFactory fac (if ssl?
                                   (SSLServerSocketFactory/getDefault)
                                   (SSLSocketFactory/getDefault))]
    (with-open [server (.createServerSocket fac port backlog (InetAddress/getByName host))]
      (loop []
        (let [socket (.accept server)
              process-fn (fn []
                           (with-open [^Socket socket socket]
                             (callback
                              (socket->input-stream socket)
                              (socket->output-stream socket))))]
          (Thread/startVirtualThread process-fn)
          (recur))))))
