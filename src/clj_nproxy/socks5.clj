(ns clj-nproxy.socks5
  "Socks5 and trojan proxy impl.
  trojan: https://trojan-gfw.github.io/trojan/protocol"
  (:require [clj-nproxy.bytes :as b]
            [clj-nproxy.struct :as st]
            [clj-nproxy.crypto :as crypto]
            [clj-nproxy.proxy :as proxy])
  (:import [java.net InetAddress]))

(set! clojure.core/*warn-on-reflection* true)

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

;;; socks5

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

(def st-socks5-pwd-auth-req
  (st/keys
   :ver st/st-ubyte
   :username st-str
   :password st-str))

(def st-socks5-pwd-auth-resp
  (st/keys
   :ver st/st-ubyte
   :status st/st-ubyte))

(def st-socks5-req
  (st/keys
   :ver st/st-ubyte
   :cmd st/st-ubyte
   :rsv st/st-ubyte
   :addr st-addr))

(def st-socks5-resp
  (st/keys
   :ver st/st-ubyte
   :status st/st-ubyte
   :rsv st/st-ubyte
   :addr st-addr))

(defn valid-socks5-ver
  "Valid ver."
  [{:keys [ver] :as socks5}]
  (if (= ver 5)
    socks5
    (throw (ex-info "invalid ver" {:reason ::invalid-socks5-ver :ver ver}))))

(defn valid-socks5-pwd-auth-ver
  "Valid auth ver."
  [{:keys [ver] :as socks5}]
  (if (= ver 1)
    socks5
    (throw (ex-info "invalid auth ver" {:reason ::invalid-socks5-pwd-auth-ver :pwd-auth-ver ver}))))

(defn valid-socks5-auth
  "Valid auth."
  [{:keys [username password] :as socks5} auth]
  (if (and (= username (:username auth)) (= password (:password auth)))
    socks5
    (throw (ex-info "invalid auth" {:reason ::invalid-auth :username username :password password}))))

(defn valid-socks5-status
  "Valid response status."
  [{:keys [status] :as resp}]
  (if (= status 0)
    resp
    (throw (ex-info "invalid status" {:reason ::invalid-socks5-status :status status}))))

(defn valid-socks5-cmd
  "Valid request cmd."
  [{:keys [cmd] :as req}]
  (if (= cmd 1)
    req
    (throw (ex-info "invalid cmd" {:reason ::invalid-cmd :cmd cmd}))))

(defmethod proxy/mk-client :socks5 [server opts host port callback]
  (let [{is :input-stream os :output-stream} server]
    ;; auth
    (let [{:keys [auth]} opts
          meths (cond-> [0] (some? auth) (conj 2))]
      (st/write-struct st-socks5-auth-req os {:ver 5 :meths meths})
      (st/flush os)
      (let [{:keys [meth]} (-> (st/read-struct st-socks5-auth-resp is) valid-socks5-ver)]
        (if (contains? (set meths) meth)
          (case (long meth)
            0 nil
            2 (let [{:keys [username password]} auth]
                (st/write-struct st-socks5-pwd-auth-req os {:ver 1 :username username :password password})
                (st/flush os)
                (-> (st/read-struct st-socks5-pwd-auth-resp is) valid-socks5-pwd-auth-ver valid-socks5-status))
            (throw (ex-info "invalid auth meth" {:reason ::invalid-auth-meth :auth-meth meth})))
          (throw (ex-info "invalid auth meth" {:reason ::invalid-auth-meth :auth-meth meth})))))
    ;; request
    (st/write-struct st-socks5-req os {:ver 5 :cmd 1 :rsv 0 :addr {:atype 3 :host host :port port}})
    (st/flush os)
    (-> (st/read-struct st-socks5-resp is) valid-socks5-ver valid-socks5-status)
    (callback {:input-stream is :output-stream os})))

(defmethod proxy/mk-server :socks5 [client opts callback]
  (let [{is :input-stream os :output-stream} client]
    ;; auth
    (let [{:keys [auth]} opts
          meth (if (some? auth) 2 0)
          {:keys [meths]} (-> (st/read-struct st-socks5-auth-req is) valid-socks5-ver)]
      (if (contains? (set meths) meth)
        (do
          (st/write-struct st-socks5-auth-resp os {:ver 5 :meth meth})
          (st/flush os)
          (case (long meth)
            0 nil
            2 (do
                (-> (st/read-struct st-socks5-pwd-auth-req is) valid-socks5-pwd-auth-ver (valid-socks5-auth auth))
                (st/write-struct st-socks5-pwd-auth-resp os {:ver 1 :status 0})
                (st/flush os))
            (throw (ex-info "invalid auth meth" {:reason ::invalid-auth-meth :auth-meth meth}))))
        (throw (ex-info "invalid auth meth" {:reason ::invalid-auth-meth :auth-meth meth}))))
    ;; request
    (let [{:keys [addr]} (-> (st/read-struct st-socks5-req is) valid-socks5-ver valid-socks5-cmd)
          {:keys [host port]} addr]
      (st/write-struct st-socks5-resp os {:ver 5 :status 0 :rsv 0 :addr {:atype 1 :host "0.0.0.0" :port 0}})
      (st/flush os)
      (callback {:input-stream is :output-stream os :host host :port port}))))

;;; trojan

(def st-trojan-req
  (st/keys
   :auth st/st-http-line
   :cmd st/st-ubyte
   :addr st-addr
   :rsv st/st-http-line))

(defmethod proxy/mk-client :trojan [server {:keys [auth]} host port callback]
  (let [{is :input-stream os :output-stream} server]
    (st/write-struct st-trojan-req os {:auth auth :cmd 1 :addr {:atype 3 :host host :port port} :rsv ""})
    (st/flush os)
    (callback {:input-stream is :output-stream os})))

(defn valid-trojan-auth
  "Valid request auth."
  [{req-auth :auth :as req} auth]
  (if (= auth req-auth)
    req
    (throw (ex-info "invalid auth" {:reason ::invalid-auth :auth req-auth}))))

(defn valid-trojan-rsv
  "Valid request rsv."
  [{:keys [rsv] :as req}]
  (if (= rsv "")
    req
    (throw (ex-info "addr surplus" {:reason ::addr-surplus}))))

(defmethod proxy/mk-server :trojan [client {:keys [auth]} callback]
  (let [{is :input-stream os :output-stream} client
        {:keys [addr]} (-> (st/read-struct st-trojan-req is)
                           (valid-trojan-auth auth)
                           valid-socks5-cmd
                           valid-trojan-rsv)
        {:keys [host port]} addr]
    (callback {:input-stream is :output-stream os :host host :port port})))

(defn trojan-auth
  "Get trojan auth."
  ^String [^String password]
  (-> password b/str->bytes crypto/sha224 b/bytes->hex))

(defn edn->trojan-opts
  "Construct trojan opts."
  [{:keys [password] :as opts}]
  (assoc opts :auth (trojan-auth password)))

(defmethod proxy/edn->client-opts :trojan [opts] (edn->trojan-opts opts))
(defmethod proxy/edn->server-opts :trojan [opts] (edn->trojan-opts opts))
