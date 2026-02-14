(ns clj-nproxy.plugin.trojan
  "Trojan proxy impl.
  https://trojan-gfw.github.io/trojan/protocol"
  (:require [clj-nproxy.bytes :as b]
            [clj-nproxy.struct :as st]
            [clj-nproxy.proxy :as proxy]
            [clj-nproxy.plugin.socks5 :as socks5])
  (:import [java.io InputStream OutputStream]
           [java.security MessageDigest]))

(def st-trojan-req
  (st/keys
   :auth st/st-http-line
   :cmd st/st-ubyte
   :addr socks5/st-addr
   :rsv st/st-http-line))

(defmethod proxy/mk-client :trojan [{:keys [auth]} ^InputStream is ^OutputStream os host port callback]
  (st/write-struct st-trojan-req os {:auth auth :cmd 1 :addr {:atype 3 :host host :port port} :rsv ""})
  (.flush os)
  (callback {:input-stream is :output-stream os}))

(defmethod proxy/mk-server :trojan [{:keys [auth]} ^InputStream is ^OutputStream os callback]
  (let [{:keys [cmd rsv] {:keys [host port]} :addr :as req} (st/read-struct st-trojan-req is)]
    (if-not (and (= auth (:auth req)) (= cmd 1) (= rsv ""))
      (throw (st/data-error))
      (callback {:input-stream is :output-stream os :host host :port port}))))

(defn trojan-auth
  "Get trojan auth."
  ^String [^String password]
  (let [d (MessageDigest/getInstance "SHA-224")]
    (b/bytes->hex (.digest d (b/str->bytes password)))))

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
