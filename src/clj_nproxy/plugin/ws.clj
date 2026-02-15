(ns clj-nproxy.plugin.ws
  "Websocket net impl."
  (:require [clojure.string :as str]
            [clj-nproxy.bytes :as b]
            [clj-nproxy.struct :as st]
            [clj-nproxy.net :as net]
            [clj-nproxy.plugin.http :as http])
  (:import [java.io InputStream OutputStream BufferedInputStream BufferedOutputStream]
           [java.security MessageDigest]))

(set! clojure.core/*warn-on-reflection* true)

(defn mask-data-inplace
  "Mask data inplace."
  [^bytes data ^bytes mask]
  (let [data (bytes data)
        mask (bytes mask)]
    (dotimes [i (alength data)]
      (aset data i (unchecked-byte (bit-xor (aget data i) (aget mask (bit-and 3 i))))))))

(defn mask-data
  "Mask data."
  ^bytes [^bytes data ^bytes mask]
  (doto (b/copy data)
    (mask-data-inplace mask)))

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
              127 (st/read-struct st/st-long-be is)
              len)]
    (if (neg? len)
      (throw (st/data-error))
      [mask? len])))

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
  [^InputStream is]
  (let [[fin? op] (read-fin-op is)
        [mask? len] (read-mask-len is)
        mask (when mask? (st/read-bytes is 4))
        data (st/read-bytes is len)]
    (when (some? mask)
      (mask-data-inplace data mask))
    {:op op :fin? fin? :mask mask :data data}))

(defn write-frame
  "Write frame to stream."
  [^OutputStream os {:keys [op fin? mask data]}]
  (write-fin-op os fin? op)
  (write-mask-len os (some? mask) (alength (bytes data)))
  (when (some? mask)
    (.write os (bytes mask)))
  (let [data (bytes (cond-> data
                      (some? mask) (mask-data mask)))]
    (.write os data)))

;; ignore ping pong: it's stupid

(defn wrap-input-stream
  "Wrap input stream."
  ^InputStream [^InputStream is]
  (let [read-fn (fn []
                  (let [{:keys [op data]} (read-frame is)]
                    (case (int op)
                      (0 9 10) (recur)
                      8 nil
                      2 (let [data (bytes data)]
                          (if-not (zero? (alength data))
                            data
                            (recur))))))]
    (BufferedInputStream.
     (st/read-fn->input-stream read-fn #(.close is)))))

(defn wrap-output-stream
  "Wrap output stream."
  ^OutputStream [^OutputStream os mask?]
  (let [write-frame-fn (fn [op data]
                         (write-frame os {:op op :fin? true :mask (when mask? (b/rand 4)) :data data})
                         (.flush os))
        write-fn (fn [b]
                   (let [b (bytes b)]
                     (when-not (zero? (alength b))
                       (write-frame-fn 2 b))))
        close-fn (fn []
                   (write-frame-fn 8 (byte-array []))
                   (.close os))]
    (BufferedOutputStream.
     (st/write-fn->output-stream write-fn close-fn))))

(def ws-uuid
  "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")

(defn key->accept
  "Get accept from key."
  ^String [^String key]
  (let [d (MessageDigest/getInstance "SHA-1")]
    (b/bytes->base64 (.digest d (b/str->bytes (str key ws-uuid))))))

^:rct/test
(comment
  (key->accept (b/bytes->base64 (byte-array 16))) ; => "ICX+Yqv66kxgM0FcWaLWlFLwTAI="
  )

(defn mk-client
  "Make websocket client."
  [opts ^InputStream is ^OutputStream os callback]
  (let [{:keys [path headers] :or {path "/"}} opts
        headers (merge {"upgrade" "websocket"
                        "connection" "upgrade"
                        "sec-websocket-key" (b/bytes->base64 (b/rand 16))
                        "sec-websocket-version" "13"}
                       headers)]
    (st/write-struct http/st-http-req os {:path path :headers headers})
    (.flush os)
    (let [{:keys [status] :as resp} (st/read-struct http/st-http-resp is)]
      (if (= status "101")
        (callback
         {:http-resp resp
          :input-stream (wrap-input-stream is)
          :output-stream (wrap-output-stream os true)})
        (throw (st/data-error))))))

(defn mk-server
  "Make websocket server."
  [opts ^InputStream is ^OutputStream os callback]
  (let [{:keys [headers] :as req} (st/read-struct http/st-http-req is)
        {:strs [upgrade sec-websocket-key]} headers]
    (if (and (= "websocket" (str/lower-case upgrade))
             (some? sec-websocket-key))
      (let [{:keys [headers]} opts
            headers (merge
                     {"upgrade" "websocket"
                      "connection" "upgrade"
                      "sec-websocket-accept" (key->accept sec-websocket-key)}
                     headers)]
        (st/write-struct http/st-http-resp os {:status "101" :reason "Switching Protocols" :headers headers})
        (.flush os)
        (callback
         {:http-req req
          :input-stream (wrap-input-stream is)
          :output-stream (wrap-output-stream os false)}))
      (throw (st/data-error)))))

(defmethod net/mk-client :ws [opts callback]
  (net/mk-client
   (assoc opts :type :tcp)
   (fn [tcp-server]
     (mk-client
      opts (:input-stream tcp-server) (:output-stream tcp-server)
      (fn [ws-server]
        (callback (merge tcp-server ws-server)))))))

(defmethod net/mk-server :ws [opts callback]
  (net/mk-server
   (assoc opts :type :tcp)
   (fn [tcp-client]
     (mk-server
      opts (:input-stream tcp-client) (:output-stream tcp-client)
      (fn [ws-client]
        (callback (merge tcp-client ws-client)))))))
