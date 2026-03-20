(ns clj-nproxy.plugin.ws
  "Websocket net impl."
  (:require [clojure.string :as str]
            [clj-nproxy.bytes :as b]
            [clj-nproxy.struct :as st]
            [clj-nproxy.crypto :as crypto]
            [clj-nproxy.net :as net]
            [clj-nproxy.plugin.http :as http])
  (:import [java.util.concurrent.locks ReentrantLock]
           [java.io InputStream OutputStream BufferedInputStream BufferedOutputStream]))

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

;;; frame

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

(defn mk-websocket
  "Make websocket."
  [stream mask? callback]
  (let [{is :input-stream os :output-stream} stream
        ^ReentrantLock lock (ReentrantLock.)
        vwclose? (volatile! false)
        vrclose? (volatile! false)
        close?-fn (fn [] @vrclose? @vwclose?)
        write-fn (fn [{:keys [op] :as frame}]
                   (when-not @vwclose?
                     (try
                       (.lock lock)
                       (when-not @vwclose?
                         (when (= op 8)
                           (vreset! vwclose? true))
                         (write-frame os (merge frame {:mask (when mask? (b/rand 4))}))
                         (st/flush os))
                       (finally
                         (.unlock lock)))))
        close-fn (fn []
                   (write-fn {:op 8 :fin? true :data (byte-array 0)}))
        ping-fn (fn [data]
                  (write-fn {:op 9 :fin? true :data data}))
        read-fn (fn []
                  (when-not @vrclose?
                    (loop []
                      (let [{:keys [op fin? data] :as frame} (read-frame is)]
                        (case (long op)
                          ;; close
                          8 (do
                              (vreset! vrclose? true)
                              (close-fn))
                          ;; ping
                          9 (do
                              (write-fn {:op 10 :fin? fin? :data data})
                              (recur))
                          ;; pong
                          10 (recur)
                          ;; continue/text/binary
                          (0 1 2) frame
                          (throw (ex-info "invalid op" {:reason ::invalid-op :op op})))))))
        wait-closed-fn (fn []
                         (loop []
                           (when-not @vrclose?
                             (read-fn)
                             (recur))))
        websocket {:stream stream
                   :close?-fn close?-fn
                   :write-fn write-fn
                   :close-fn close-fn
                   :ping-fn ping-fn
                   :read-fn read-fn
                   :wait-closed-fn wait-closed-fn}]
    (try
      (callback websocket)
      (finally
        (close-fn)
        (wait-closed-fn)
        (st/close is)
        (st/close os)))))

;;; handshake

(def ws-uuid
  "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")

(defn key->accept
  "Get accept from key."
  ^String [^String key]
  (-> (str key ws-uuid) b/str->bytes crypto/sha1 b/bytes->base64))

^:rct/test
(comment
  (key->accept (b/bytes->base64 (byte-array 16))) ; => "ICX+Yqv66kxgM0FcWaLWlFLwTAI="
  )

(defn mk-websocket-client
  "Make websocket client."
  [server opts callback]
  (let [{is :input-stream os :output-stream} server
        {:keys [path headers] :or {path "/"}} opts
        headers (merge
                 headers
                 {"upgrade" "websocket"
                  "connection" "upgrade"
                  "sec-websocket-key" (b/bytes->base64 (b/rand 16))
                  "sec-websocket-version" "13"})]
    (st/write-struct http/st-http-req os {:path path :headers headers})
    (st/flush os)
    (let [resp (-> (st/read-struct http/st-http-resp is)
                   http/valid-version
                   (http/valid-status "101")
                   (http/valid-connection "websocket"))]
      (mk-websocket server true #(callback (merge % {:http-resp resp}))))))

(defn mk-websocket-server
  "Make websocket server."
  [client opts callback]
  (let [{is :input-stream os :output-stream} client
        {:keys [headers]} opts
        req (-> (st/read-struct http/st-http-req is)
                http/valid-version
                (http/valid-method "get")
                (http/valid-connection "websocket"))
        accept (-> req (get-in [:headers "sec-websocket-key"]) key->accept)
        headers (merge
                 headers
                 {"upgrade" "websocket"
                  "connection" "upgrade"
                  "sec-websocket-accept" accept})]
    (st/write-struct http/st-http-resp os {:status "101" :reason "Switching Protocols" :headers headers})
    (st/flush os)
    (mk-websocket client false #(callback (merge % {:http-req req})))))

;;; stream

(defn websocket->input-stream
  "Convert websocket to input stream."
  ^InputStream [{:keys [read-fn]}]
  (BufferedInputStream.
   (st/read-fn->input-stream
    (fn []
      (when-let [{:keys [data]} (read-fn)]
        (if-not (zero? (b/length data))
          data
          (recur)))))))

(defn websocket->output-stream
  "Convert websocket to output stream."
  ^OutputStream [{:keys [write-fn]}]
  (BufferedOutputStream.
   (st/write-fn->output-stream
    (fn [b]
      (when-not (zero? (b/length b))
        (write-fn {:op 2 :fin? true :data b}))))))

(defn websocket->stream
  "Convert websocket to stream."
  [websocket]
  {:websocket websocket
   :input-stream (websocket->input-stream websocket)
   :output-stream (websocket->output-stream websocket)})

(defn mk-client
  "Make websocket client."
  [server opts callback]
  (mk-websocket-client
   server opts
   (fn [server]
     (callback (websocket->stream server)))))

(defn mk-server
  "Make websocket server."
  [client opts callback]
  (mk-websocket-server
   client opts
   (fn [client]
     (callback (websocket->stream client)))))

(defmethod net/mk-client :ws [opts callback]
  (net/mk-client
   (assoc opts :type :tcp)
   (fn [tcp-server]
     (mk-client
      tcp-server opts
      (fn [ws-server]
        (callback (merge tcp-server ws-server)))))))

(defmethod net/mk-server :ws [opts callback]
  (net/mk-server
   (assoc opts :type :tcp)
   (fn [tcp-client]
     (mk-server
      tcp-client opts
      (fn [ws-client]
        (callback (merge tcp-client ws-client)))))))
