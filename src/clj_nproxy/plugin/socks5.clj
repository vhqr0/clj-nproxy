(ns clj-nproxy.plugin.socks5
  (:require [clj-nproxy.struct :as st]
            [clj-nproxy.proxy :as proxy])
  (:import [java.io InputStream OutputStream]
           [java.net InetAddress]))

(def st-str (-> (st/->st-var-bytes st/st-ubyte) st/wrap-str))

(defn wrap-ip
  "Wrap bytes struct to ip address struct."
  [st-bytes]
  (st/wrap
   st-bytes
   #(.getHostAddress (InetAddress/getByAddress (bytes %)))
   #(.getAddress (InetAddress/getByName (str %)))))

(def st-ipv4 (-> (st/->st-bytes 4) wrap-ip))
(def st-ipv6 (-> (st/->st-bytes 16) wrap-ip))

(def st-host
  (fn [{:keys [atype]}]
    (case (long atype)
      3 st-str
      1 st-ipv4
      4 st-ipv6)))

(def st-addr
  (st/keys
   :atype st/st-ubyte
   :host st-host
   :port st/st-ushort-be))

(def st-auth-req
  (st/keys
   :ver st/st-ubyte
   :meths (-> (st/->st-var-bytes st/st-ubyte)
              (st/wrap
               (partial st/unpack-many st/st-ubyte)
               (partial st/pack-many st/st-ubyte)))))

(def st-auth-resp
  (st/keys
   :ver st/st-ubyte
   :meth st/st-ubyte))

(def st-req
  (st/keys
   :ver st/st-ubyte
   :cmd st/st-ubyte
   :rsv st/st-ubyte
   :addr st-addr))

(def st-resp
  (st/keys
   :ver st/st-ubyte
   :status st/st-ubyte
   :rsv st/st-ubyte
   :addr st-addr))

(defmethod proxy/mk-client :socks5 [_opts ^InputStream is ^OutputStream os host port callback]
  (st/write-struct st-auth-req os {:ver 5 :meths [0]})
  (.flush os)
  (let [{:keys [ver meth]} (st/read-struct st-auth-resp is)]
    (if-not (and (= ver 5) (= meth 0))
      (throw (st/data-error))
      (do
        (st/write-struct st-req os {:ver 5 :cmd 1 :rsv 0 :addr {:atype 3 :host host :port port}})
        (.flush os)
        (let [{:keys [ver status]} (st/read-struct st-resp is)]
          (if-not (and (= ver 5) (= status 0))
            (throw (st/data-error))
            (callback {:input-stream is :output-stream os})))))))

(defmethod proxy/mk-server :socks5 [_opts ^InputStream is ^OutputStream os callback]
  (let [{:keys [ver meths]} (st/read-struct st-auth-req is)]
    (if-not (and (= ver 5) (contains? (set meths) 0))
      (throw (st/data-error))
      (do
        (st/write-struct st-auth-resp os {:ver 5 :meth 0})
        (.flush os)
        (let [{:keys [ver cmd] {:keys [host port]} :addr} (st/read-struct st-req is)]
          (if-not (and (= ver 5) (= cmd 1))
            (throw (st/data-error))
            (do
              (st/write-struct st-resp os {:ver 5 :status 0 :rsv 0 :addr {:atype 1 :host "0.0.0.0" :port 0}})
              (.flush os)
              (callback {:input-stream is :output-stream os :host host :port port}))))))))
