(ns clj-nproxy.experiment.unix
  "Unix domain socket net impl."
  (:require [clj-nproxy.struct :as st]
            [clj-nproxy.net :as net])
  (:import [java.io InputStream OutputStream BufferedInputStream BufferedOutputStream]
           [java.nio.channels Channels SocketChannel ServerSocketChannel]
           [java.net UnixDomainSocketAddress StandardProtocolFamily]))

(set! clojure.core/*warn-on-reflection* true)

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
  {:path (str (.getRemoteAddress sc))})

(defn socket-channel->stream
  "Convert socket channel to stream."
  [^SocketChannel sc]
  {:socket-channel sc
   :peer (socket-channel->peer sc)
   :input-stream (socket-channel->input-stream sc)
   :output-stream (socket-channel->output-stream sc)})

(defn socket-channel-callback
  "Convert socket to stream, then invoke callback fn."
  [^SocketChannel sc callback]
  (with-open [sc sc]
    (callback (socket-channel->stream sc))))

(defn start-server-socket-channel
  "Start server socket channel."
  [^ServerSocketChannel server callback]
  (with-open [server server]
    (loop []
      (let [sc (.accept server)]
        (Thread/startVirtualThread
         #(socket-channel-callback sc callback))
        (recur)))))

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
