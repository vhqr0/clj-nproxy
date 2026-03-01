(ns clj-nproxy.plugin.socks5
  (:require [clj-nproxy.struct :as st]
            [clj-nproxy.proxy :as proxy])
  (:import [java.net InetAddress]))

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
      4 st-ipv6
      (throw (ex-info "invalid atype" {:reason ::invalid-atype :atype atype})))))

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

(defn valid-ver
  "Valid ver."
  [{:keys [ver] :as socks5}]
  (if (= ver 5)
    socks5
    (throw (ex-info "invalid ver" {:reason ::invalid-ver :ver 5}))))

(defn valid-meths
  "Valid auth request meth."
  [{:keys [meths] :as auth-req}]
  (if (contains? (set meths) 0)
    auth-req
    (throw (ex-info "invalid meths" {:reason ::invalid-meths :meths meths}))))

(defn valid-meth
  "Valid auth response meth."
  [{:keys [meth] :as auth-resp}]
  (if (= meth 0)
    auth-resp
    (throw (ex-info "invalid meth" {:reason ::invalid-meth :meth meth}))))

(defn valid-cmd
  "Valid request cmd."
  [{:keys [cmd] :as req}]
  (if (= cmd 1)
    req
    (throw (ex-info "invalid cmd" {:reason ::invalid-cmd :cmd cmd}))))

(defn valid-status
  "Valid response status."
  [{:keys [status] :as resp}]
  (if (= status 0)
    resp
    (throw (ex-info "invalid status" {:reason ::invalid-status :status status}))))

(defmethod proxy/mk-client :socks5 [_opts server host port callback]
  (let [{is :input-stream os :output-stream} server]
    (st/write-struct st-auth-req os {:ver 5 :meths [0]})
    (st/flush os)
    (-> (st/read-struct st-auth-resp is) valid-ver valid-meth)
    (st/write-struct st-req os {:ver 5 :cmd 1 :rsv 0 :addr {:atype 3 :host host :port port}})
    (st/flush os)
    (-> (st/read-struct st-resp is) valid-ver valid-status)
    (callback {:input-stream is :output-stream os})))

(defmethod proxy/mk-server :socks5 [_opts client callback]
  (let [{is :input-stream os :output-stream} client]
    (-> (st/read-struct st-auth-req is) valid-ver valid-meths)
    (st/write-struct st-auth-resp os {:ver 5 :meth 0})
    (st/flush os)
    (let [{:keys [addr]} (-> (st/read-struct st-req is) valid-ver valid-cmd)
          {:keys [host port]} addr]
      (st/write-struct st-resp os {:ver 5 :status 0 :rsv 0 :addr {:atype 1 :host "0.0.0.0" :port 0}})
      (st/flush os)
      (callback {:input-stream is :output-stream os :host host :port port}))))
