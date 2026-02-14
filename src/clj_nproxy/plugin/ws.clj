(ns clj-nproxy.plugin.ws
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

(defn read-mask-len
  "Read length from stream."
  [is]
  (let [mask-len (st/read-ubyte is)
        mask (bit-and 0x80 mask-len)
        len (bit-and 0x7f mask-len)
        len (case len
              126 (st/read-struct st/st-ushort-be is)
              127 (st/read-struct st/st-long-be is)
              len)]
    (if (neg? len)
      (throw (st/data-error))
      [mask len])))

(defn write-mask-len
  "Write length to stream."
  [os mask len]
  (cond
    (< len 126)
    (st/write-struct st/st-ubyte os (+ len (bit-shift-left mask 7)))
    (< len 65536)
    (do
      (st/write-struct st/st-ubyte os (+ 126 (bit-shift-left mask 7)))
      (st/write-struct st/st-ushort-be os len))
    :else
    (do
      (st/write-struct st/st-ubyte os (+ 127 (bit-shift-left mask 7)))
      (st/write-struct st/st-long-be os len))))

(defn read-frame
  "Read frame from stream."
  [^InputStream is]
  (let [fin-op (st/read-ubyte is)
        fin (bit-and 0x80 fin-op)
        op (bit-and 0x7f fin-op)
        fin? (not (zero? fin))
        [mask len] (read-mask-len is)
        mask? (not (zero? mask))
        mask (when mask? (st/read-bytes is 4))
        data (st/read-bytes is len)]
    (when (some? mask)
      (mask-data-inplace data mask))
    {:op op :fin? fin? :mask mask :data data}))

(defn write-frame
  "Write frame to stream."
  [^OutputStream os {:keys [op fin? mask data]}]
  (.write os (int (+ op (bit-shift-left (if fin? 1 0) 7))))
  (write-mask-len os (if (some? mask) 1 0) (alength (bytes data)))
  (when (some? mask)
    (.write os (bytes mask)))
  (let [data (bytes (if (nil? mask)
                      data
                      (doto (b/copy data)
                        (mask-data-inplace mask))))]
    (.write os data)))

(defn wrap-input-stream
  "Wrap input stream."
  ^InputStream [^InputStream is apings]
  (let [vlast (volatile! nil)
        read-frame-fn (fn []
                        (let [{:keys [op fin? data]} (read-frame is)
                              data (if-let [[lop ldata] @vlast]
                                     (if (= op lop)
                                       (b/cat ldata data)
                                       (throw (st/data-error)))
                                     data)]
                          (if fin?
                            [op data]
                            (do
                              (vreset! vlast [op data])
                              (recur)))))
        read-fn (fn []
                  (let [[op data] (read-frame-fn)]
                    (case (int op)
                      ;; continue
                      0 (recur)
                      ;; text
                      1 (throw (st/data-error))
                      ;; binary
                      2 (if-not (zero? (alength (bytes data))) data (recur))
                      ;; close
                      8 nil
                      ;; ping
                      9 (do (swap! apings conj data) (recur))
                      ;; pong
                      10 (recur))))]
    (BufferedInputStream.
     (st/read-fn->input-stream read-fn #(.close is)))))

(defn wrap-output-stream
  "Wrap output stream."
  ^OutputStream [^OutputStream os apings mask?]
  (let [write-frame-fn (fn [op data]
                         (write-frame os {:op op :fin? true :mask (when mask? (b/rand 4)) :data data})
                         (.flush os))
        write-pongs-fn (fn []
                         (when-let [ping (first @apings)]
                           (write-frame-fn 10 ping)
                           (swap! apings (comp vec rest))
                           (recur)))
        write-fn (fn [b]
                   (let [b (bytes b)]
                     (when-not (zero? (alength b))
                       (write-pongs-fn)
                       (write-frame-fn 2 b))))
        close-fn (fn []
                   (write-pongs-fn)
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
        (let [apings (atom [])]
          (callback
           {:http-resp resp
            :input-stream (wrap-input-stream is apings)
            :output-stream (wrap-output-stream os apings true)}))
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
        (let [apings (atom [])]
          (callback
           {:http-req req
            :input-stream (wrap-input-stream is apings)
            :output-stream (wrap-output-stream os apings false)})))
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
