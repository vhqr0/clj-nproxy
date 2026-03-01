(ns clj-nproxy.plugin.ws
  "Websocket net impl."
  (:require [clojure.string :as str]
            [clj-nproxy.bytes :as b]
            [clj-nproxy.struct :as st]
            [clj-nproxy.crypto :as crypto]
            [clj-nproxy.net :as net]
            [clj-nproxy.plugin.http :as http])
  (:import [java.io BufferedInputStream BufferedOutputStream]))

(set! clojure.core/*warn-on-reflection* true)

(def st-fake-ulong-be
  (-> st/st-long-be (st/wrap-validator nat-int?)))

(defn mask-data-inplace
  "Mask data inplace."
  [^bytes data ^bytes mask]
  (let [data (bytes data)
        mask (bytes mask)]
    (dotimes [idx (alength data)]
      (let [i (aget mask (bit-and 3 idx))]
        (aset data idx (unchecked-byte (bit-xor i (aget data idx))))))))

(defn read-fin-op
  "Read op from stream."
  [is]
  (let [fin-op (st/read-ubyte is)
        fin (bit-and 0x80 fin-op)
        op (bit-and 0x7f fin-op)
        fin? (not (zero? fin))]
    [fin? op]))

(defn write-fin-op
  "Write op to stream."
  [os fin? op]
  (st/write-struct st/st-ubyte os (+ op (if fin? 128 0))))

(defn read-mask-len
  "Read length from stream."
  [is]
  (let [mask-len (st/read-ubyte is)
        mask (bit-and 0x80 mask-len)
        len (bit-and 0x7f mask-len)
        mask? (not (zero? mask))
        len (case len
              126 (st/read-struct st/st-ushort-be is)
              127 (st/read-struct st-fake-ulong-be is)
              len)]
    [mask? len]))

(defn write-mask-len
  "Write length to stream."
  [os mask? len]
  (cond
    (< len 126)
    (st/write-struct st/st-ubyte os (+ len (if mask? 128 0)))
    (< len 65536)
    (do
      (st/write-struct st/st-ubyte os (+ 126 (if mask? 128 0)))
      (st/write-struct st/st-ushort-be os len))
    :else
    (do
      (st/write-struct st/st-ubyte os (+ 127 (if mask? 128 0)))
      (st/write-struct st/st-long-be os len))))

(defn read-frame
  "Read frame from stream."
  [is]
  (let [[fin? op] (read-fin-op is)
        [mask? len] (read-mask-len is)
        mask (when mask? (st/read-bytes is 4))
        data (st/read-bytes is len)]
    (when (some? mask)
      (mask-data-inplace data mask))
    {:op op :fin? fin? :mask mask :data data}))

(defn write-frame
  "Write frame to stream."
  [os {:keys [op fin? mask data]}]
  (write-fin-op os fin? op)
  (write-mask-len os (some? mask) (b/length data))
  (when (some? mask)
    (st/write os mask)
    (mask-data-inplace data mask))
  (st/write os data))

;; ignore ping pong: it's stupid

(defn wrap-input-stream
  "Wrap input stream."
  [is]
  (let [read-fn (fn []
                  (let [{:keys [op data]} (read-frame is)]
                    (case (int op)
                      (0 9 10) (recur)
                      8 nil
                      2 (if-not (zero? (b/length data))
                          data
                          (recur))
                      (throw (ex-info "invalid op" {:reason ::invalid-op :op op})))))]
    (BufferedInputStream.
     (st/read-fn->input-stream read-fn #(st/close is)))))

(defn wrap-output-stream
  "Wrap output stream."
  [os mask?]
  (let [write-frame-fn (fn [op data]
                         (write-frame os {:op op :fin? true :mask (when mask? (b/rand 4)) :data data})
                         (st/flush os))
        write-fn (fn [b]
                   (when-not (zero? (b/length b))
                     (write-frame-fn 2 b)))
        close-fn (fn []
                   (write-frame-fn 8 (byte-array []))
                   (st/close os))]
    (BufferedOutputStream.
     (st/write-fn->output-stream write-fn close-fn))))

(def ws-uuid
  "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")

(defn key-gen
  "Generate key."
  []
  (b/bytes->base64 (b/rand 16)))

(defn key->accept
  "Get accept from key."
  ^String [^String key]
  (-> (str key ws-uuid) b/str->bytes crypto/sha1 b/bytes->base64))

^:rct/test
(comment
  (key->accept (b/bytes->base64 (byte-array 16))) ; => "ICX+Yqv66kxgM0FcWaLWlFLwTAI="
  )

(defn valid-connection
  "Valid request/response connection."
  [{:keys [headers] :as http}]
  (let [{:strs [connection upgrade]} headers
        connection (some-> connection str/lower-case)
        upgrade (some-> upgrade str/lower-case)]
    (if (= connection "upgrade")
      (if (= upgrade "websocket")
        http
        (throw (ex-info "invalid upgrade" {:reason ::invalid-upgrade :upgrade upgrade})))
      (throw (ex-info "invalid connection" {:reason ::invalid-connection :connection connection})))))

(defn valid-accept
  "Valid response accept."
  [{:keys [headers] :as resp} key]
  (let [accept (get headers "sec-websocket-accept")]
    (if (= accept (key->accept key))
      resp
      (throw (ex-info "invalid accept" {:reason ::invalid-accept})))))

(defn mk-client
  "Make websocket client."
  [opts server callback]
  (let [{is :input-stream os :output-stream} server
        {:keys [path headers] :or {path "/"}} opts
        key (key-gen)
        headers (merge
                 headers
                 {"upgrade" "websocket"
                  "connection" "upgrade"
                  "sec-websocket-key" key
                  "sec-websocket-version" "13"})]
    (st/write-struct http/st-http-req os {:path path :headers headers})
    (st/flush os)
    (let [resp (-> (st/read-struct http/st-http-resp is)
                   http/valid-version
                   (http/valid-status "101")
                   valid-connection
                   (valid-accept key))]
      (callback
       {:http-resp resp
        :input-stream (wrap-input-stream is)
        :output-stream (wrap-output-stream os true)}))))

(defn mk-server
  "Make websocket server."
  [opts client callback]
  (let [{is :input-stream os :output-stream} client
        {:keys [headers]} opts
        req (-> (st/read-struct http/st-http-req is)
                http/valid-version
                (http/valid-method "get")
                valid-connection)
        accept (-> req (get-in [:headers "sec-websocket-key"]) key->accept)
        headers (merge
                 headers
                 {"upgrade" "websocket"
                  "connection" "upgrade"
                  "sec-websocket-accept" accept})]
    (st/write-struct http/st-http-resp os {:status "101" :reason "Switching Protocols" :headers headers})
    (st/flush os)
    (callback
     {:http-req req
      :input-stream (wrap-input-stream is)
      :output-stream (wrap-output-stream os false)})))

(defmethod net/mk-client :ws [opts callback]
  (net/mk-client
   (assoc opts :type :tcp)
   (fn [tcp-server]
     (mk-client
      opts tcp-server
      (fn [ws-server]
        (callback (merge tcp-server ws-server)))))))

(defmethod net/mk-server :ws [opts callback]
  (net/mk-server
   (assoc opts :type :tcp)
   (fn [tcp-client]
     (mk-server
      opts tcp-client
      (fn [ws-client]
        (callback (merge tcp-client ws-client)))))))
