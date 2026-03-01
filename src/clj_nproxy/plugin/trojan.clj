(ns clj-nproxy.plugin.trojan
  "Trojan proxy impl.
  https://trojan-gfw.github.io/trojan/protocol"
  (:require [clj-nproxy.bytes :as b]
            [clj-nproxy.struct :as st]
            [clj-nproxy.crypto :as crypto]
            [clj-nproxy.proxy :as proxy]
            [clj-nproxy.plugin.socks5 :as socks5]))

(set! clojure.core/*warn-on-reflection* true)

(def st-req
  (st/keys
   :auth st/st-http-line
   :cmd st/st-ubyte
   :addr socks5/st-addr
   :rsv st/st-http-line))

(defmethod proxy/mk-client :trojan [{:keys [auth]} server host port callback]
  (let [{is :input-stream os :output-stream} server]
    (st/write-struct st-req os {:auth auth :cmd 1 :addr {:atype 3 :host host :port port} :rsv ""})
    (st/flush os)
    (callback {:input-stream is :output-stream os})))

(defn valid-auth
  "Valid request auth."
  [{req-auth :auth :as req} auth]
  (if (= auth req-auth)
    req
    (throw (ex-info "invalid auth" {:reason ::invalid-auth :auth req-auth}))))

(defn valid-cmd
  "Valid request cmd."
  [{:keys [cmd] :as req}]
  (if (= cmd 1)
    req
    (throw (ex-info "invalid cmd" {:reason ::invalid-cmd :cmd cmd}))))

(defn valid-rsv
  "Valid request rsv."
  [{:keys [rsv] :as req}]
  (if (= rsv "")
    req
    (throw (ex-info "addr surplus" {:reason ::addr-surplus}))))

(defmethod proxy/mk-server :trojan [{:keys [auth]} client callback]
  (let [{is :input-stream os :output-stream} client
        {:keys [addr]} (-> (st/read-struct st-req is)
                           (valid-auth auth)
                           valid-cmd
                           valid-rsv)
        {:keys [host port]} addr]
    (callback {:input-stream is :output-stream os :host host :port port})))

(defn trojan-auth
  "Get trojan auth."
  ^String [^String password]
  (-> password b/str->bytes crypto/sha224 b/bytes->hex))

^:rct/test
(comment
  (trojan-auth "hello") ; => "ea09ae9cc6768c50fcee903ed054556e5bfc8347907f12598aa24193"
  )

(defn edn->trojan-opts
  "Construct trojan opts."
  [{:keys [password] :as opts}]
  (assoc opts :auth (trojan-auth password)))

(defmethod proxy/edn->client-opts :trojan [opts] (edn->trojan-opts opts))
(defmethod proxy/edn->server-opts :trojan [opts] (edn->trojan-opts opts))
