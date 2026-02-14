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

;;; socks5

(def st-socks5-str (-> (st/->st-var-bytes st/st-ubyte) st/wrap-str))

(defn socks5-wrap-ip
  "Wrap bytes struct to ip address struct."
  [st-bytes]
  (st/wrap
   st-bytes
   #(.getHostAddress (InetAddress/getByAddress (bytes %)))
   #(.getAddress (InetAddress/getByName (str %)))))

(def st-socks5-ipv4 (-> (st/->st-bytes 4) socks5-wrap-ip))
(def st-socks5-ipv6 (-> (st/->st-bytes 16) socks5-wrap-ip))

(def st-socks5-host
  (fn [{:keys [atype]}]
    (case (long atype)
      3 st-socks5-str
      1 st-socks5-ipv4
      4 st-socks5-ipv6)))

(def st-socks5-addr
  (st/keys
   :atype st/st-ubyte
   :host st-socks5-host
   :port st/st-ushort-be))

(def st-socks5-auth-req
  (st/keys
   :ver st/st-ubyte
   :meths (-> (st/->st-var-bytes st/st-ubyte)
              (st/wrap
               (partial st/unpack-many st/st-ubyte)
               (partial st/pack-many st/st-ubyte)))))

(def st-socks5-auth-resp
  (st/keys
   :ver st/st-ubyte
   :meth st/st-ubyte))

(def st-socks5-req
  (st/keys
   :ver st/st-ubyte
   :cmd st/st-ubyte
   :rsv st/st-ubyte
   :addr st-socks5-addr))

(def st-socks5-resp
  (st/keys
   :ver st/st-ubyte
   :status st/st-ubyte
   :rsv st/st-ubyte
   :addr st-socks5-addr))

(defmethod mk-client :socks5 [_opts ^InputStream is ^OutputStream os host port callback]
  (st/write-struct st-socks5-auth-req os {:ver 5 :meths [0]})
  (.flush os)
  (let [{:keys [ver meth]} (st/read-struct st-socks5-auth-resp is)]
    (if-not (and (= ver 5) (= meth 0))
      (throw (st/data-error))
      (do
        (st/write-struct st-socks5-req os {:ver 5 :cmd 1 :rsv 0 :addr {:atype 3 :host host :port port}})
        (.flush os)
        (let [{:keys [ver status]} (st/read-struct st-socks5-resp is)]
          (if-not (and (= ver 5) (= status 0))
            (throw (st/data-error))
            (callback {:input-stream is :output-stream os})))))))

(defmethod mk-server :socks5 [_opts ^InputStream is ^OutputStream os callback]
  (let [{:keys [ver meths]} (st/read-struct st-socks5-auth-req is)]
    (if-not (and (= ver 5) (contains? (set meths) 0))
      (throw (st/data-error))
      (do
        (st/write-struct st-socks5-auth-resp os {:ver 5 :meth 0})
        (.flush os)
        (let [{:keys [ver cmd] {:keys [host port]} :addr} (st/read-struct st-socks5-req is)]
          (if-not (and (= ver 5) (= cmd 1))
            (throw (st/data-error))
            (do
              (st/write-struct st-socks5-resp os {:ver 5 :status 0 :rsv 0 :addr {:atype 1 :host "0.0.0.0" :port 0}})
              (.flush os)
              (callback {:input-stream is :output-stream os :host host :port port}))))))))
