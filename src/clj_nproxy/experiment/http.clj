(ns clj-nproxy.experiment.http
  "HTTP proxy and websocket net impl."
  (:require [clojure.string :as str]
            [clj-nproxy.bytes :as b]
            [clj-nproxy.struct :as st]
            [clj-nproxy.crypto :as crypto]
            [clj-nproxy.net :as net]
            [clj-nproxy.proxy :as proxy])
  (:import [java.util.concurrent.locks ReentrantLock]
           [java.io InputStream OutputStream ByteArrayInputStream SequenceInputStream]))

(set! clojure.core/*warn-on-reflection* true)

(defn unpack-header
  "Unpack text to header kv."
  [^String s]
  (let [kv (str/split s #":" 2)]
    (if (= 2 (count kv))
      (let [[k v] kv]
        [(str/lower-case (str/trim k)) (str/trim v)])
      (throw (ex-info "invalid header" {:reason ::invalid-header :header s})))))

(defn unpack-http
  "Unpack text (before \r\n\r\n) to http."
  [^String s]
  (let [lines (str/split s #"\r\n" -1)
        first-line (first lines)
        headers (->> (rest lines) (map unpack-header) (into {}))]
    [first-line headers]))

(defn pack-http
  "Pack http (before \r\n\r\n) to text."
  ^String [first-line headers]
  (let [lines (->> headers (map (fn [[k v]] (str k ": " v))))]
    (->> (cons first-line lines) (str/join "\r\n"))))

(defn unpack-reqline
  "Unpack request line."
  [^String s]
  (let [sp (str/split s #"\s+" 3)]
    (if (= 3 (count sp))
      sp
      (throw (ex-info "invalid request line" {:reason ::invalid-reqline :reqline s})))))

(defn unpack-req
  "Unpack request."
  [^String s]
  (let [[first-line headers] (unpack-http s)
        [method path version] (unpack-reqline first-line)]
    {:method method :path path :version version :headers headers}))

(defn pack-req
  "Pack request."
  ^String [{:keys [method path version headers]
            :or {method "GET" path "/" version "HTTP/1.1"}}]
  (pack-http (format "%s %s %s" method path version) headers))

(defn unpack-respline
  "Unpack response line."
  [^String s]
  (let [sp (str/split s #"\s+" 3)]
    (if (= 3 (count sp))
      sp
      (throw (ex-info "invalid response line" {:reason ::invalid-respline :respline s})))))

(defn unpack-resp
  "Unpack response."
  [^String s]
  (let [[first-line headers] (unpack-http s)
        [version status reason] (unpack-respline first-line)]
    {:version version :status status :reason reason :headers headers}))

(defn pack-resp
  "Pack response."
  ^String [{:keys [version status reason headers]
            :or {version "HTTP/1.1" status "200" reason "OK"}}]
  (pack-http (format "%s %s %s" version status reason) headers))

(def st-http-req
  (-> (st/->st-line "\r\n\r\n")
      (st/wrap unpack-req pack-req)))

(def st-http-resp
  (-> (st/->st-line "\r\n\r\n")
      (st/wrap unpack-resp pack-resp)))

(def hostport-re #"^([^:]+)(:(\d+))?$")
(def bracketed-hostport-re #"^\[([^\[\]]+)\](:(\d+))?$")

(defn unpack-hostport
  "Unpack host port."
  [^String s]
  (let [re (if (= \[ (first s)) bracketed-hostport-re hostport-re)]
    (if-let [matches (re-matches re s)]
      (let [host (get matches 1)
            port (some-> (get matches 3) parse-long)]
        [host port])
      (throw (ex-info "invalid hostport" {:reason ::invalid-hostport :hostport s})))))

(defn pack-hostport
  "Pack host port."
  ^String [host port]
  (let [fmt (if (str/index-of host ":") "[%s]:%d" "%s:%d")]
    (format fmt host port)))

(defn valid-version
  "Valid request/response version."
  [{:keys [version] :as http}]
  (if (= "http/1.1" (str/lower-case version))
    http
    (throw (ex-info "invalid version" {:reason ::invalid-version :version version}))))

(defn valid-method
  "Valid request method."
  [{req-method :method :as req} method]
  (if (= method (str/lower-case req-method))
    req
    (throw (ex-info "invalid method" {:reason ::invalid-method :method req-method}))))

(defn valid-status
  "Valid response status."
  [{resp-status :status :as resp} status]
  (if (= status resp-status)
    resp
    (throw (ex-info "invalid status" {:reason ::invalid-status :status resp-status}))))

(defn valid-connection
  "Valid request/response connection."
  [{:keys [headers] :as http} protocol]
  (let [{:strs [connection upgrade]} headers
        connection (some-> connection str/lower-case)
        upgrade (some-> upgrade str/lower-case)]
    (if (= connection "upgrade")
      (if (= upgrade protocol)
        http
        (throw (ex-info "invalid upgrade" {:reason ::invalid-upgrade :upgrade upgrade})))
      (throw (ex-info "invalid connection" {:reason ::invalid-connection :connection connection})))))

(defmethod proxy/mk-client :http [server {:keys [headers]} host port callback]
  (let [{is :input-stream os :output-stream} server
        hostport (pack-hostport host port)
        headers (merge {"host" hostport} headers)]
    (st/write-struct st-http-req os {:method "CONNECT" :path hostport :headers headers})
    (st/flush os)
    (let [resp (-> (st/read-struct st-http-resp is) valid-version (valid-status "200"))]
      (callback {:http-resp resp :input-stream is :output-stream os}))))

(defmethod proxy/mk-server :http [client _opts callback]
  (let [{is :input-stream os :output-stream} client
        {:keys [method] :as req} (-> (st/read-struct st-http-req is) valid-version)]
    (if (= "connect" (str/lower-case method))
      ;; connect
      (let [{:keys [path]} req
            [host port] (unpack-hostport path)]
        (st/write-struct st-http-resp os {:headers {"connection" "close"}})
        (st/flush os)
        (callback {:http-req req :input-stream is :output-stream os :host host :port (or port 443)}))
      ;; get, post, ...
      (let [{:keys [headers]} req
            [host port] (or (some-> (get headers "host") unpack-hostport)
                            (ex-info "no hostport" {:reason ::no-hostport}))
            ;; remove proxy- headers
            headers (->> headers
                         (remove
                          (fn [[k _v]]
                            (str/starts-with? k "proxy-")))
                         (into {}))
            req-bytes (st/pack st-http-req (assoc req :headers headers))
            req-is (ByteArrayInputStream. req-bytes)
            is (SequenceInputStream. req-is is)]
        (callback {:http-req req :input-stream is :output-stream os :host host :port (or port 80)})))))

;;; websocket

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

;;;; frame

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
        close?-fn (fn [] (or @vrclose? @vwclose?))
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
                   (write-fn {:op 8 :fin? true :data (st/pack-ushort-be 1000)}))
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

;;;; handshake

(def websocket-uuid
  "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")

(defn websocket-key->accept
  "Get accept from key."
  ^String [^String key]
  (-> (str key websocket-uuid) b/str->bytes crypto/sha1 b/bytes->base64))

(defn mk-client-websocket
  "Make client websocket."
  [server opts callback]
  (let [{is :input-stream os :output-stream} server
        {:keys [path headers] :or {path "/"}} opts
        headers (merge
                 headers
                 {"upgrade" "websocket"
                  "connection" "upgrade"
                  "sec-websocket-key" (b/bytes->base64 (b/rand 16))
                  "sec-websocket-version" "13"})]
    (st/write-struct st-http-req os {:path path :headers headers})
    (st/flush os)
    (let [resp (-> (st/read-struct st-http-resp is)
                   valid-version
                   (valid-status "101")
                   (valid-connection "websocket"))]
      (mk-websocket server true #(callback (merge % {:http-resp resp}))))))

(defn mk-server-websocket
  "Make server websocket."
  [client opts callback]
  (let [{is :input-stream os :output-stream} client
        {:keys [headers]} opts
        req (-> (st/read-struct st-http-req is)
                valid-version
                (valid-method "get")
                (valid-connection "websocket"))
        accept (-> req (get-in [:headers "sec-websocket-key"]) websocket-key->accept)
        headers (merge
                 headers
                 {"upgrade" "websocket"
                  "connection" "upgrade"
                  "sec-websocket-accept" accept})]
    (st/write-struct st-http-resp os {:status "101" :reason "Switching Protocols" :headers headers})
    (st/flush os)
    (mk-websocket client false #(callback (merge % {:http-req req})))))

;;;; stream

(defn websocket->input-stream
  "Convert websocket to input stream."
  ^InputStream [{:keys [read-fn]}]
  (st/read-fn->buffered-input-stream
   (fn []
     (when-let [{:keys [data]} (read-fn)]
       (if-not (zero? (b/length data))
         data
         (recur))))))

(defn websocket->output-stream
  "Convert websocket to output stream."
  ^OutputStream [{:keys [write-fn]}]
  (st/write-fn->buffered-output-stream
   (fn [b]
     (when-not (zero? (b/length b))
       (write-fn {:op 2 :fin? true :data b})))))

(defn websocket->stream
  "Convert websocket to stream."
  [websocket]
  {:websocket websocket
   :input-stream (websocket->input-stream websocket)
   :output-stream (websocket->output-stream websocket)})

(defn mk-websocket-client
  "Make websocket client."
  [server opts callback]
  (mk-client-websocket
   server opts
   (fn [server]
     (callback (websocket->stream server)))))

(defn mk-websocket-server
  "Make websocket server."
  [client opts callback]
  (mk-server-websocket
   client opts
   (fn [client]
     (callback (websocket->stream client)))))

#_(defmethod net/mk-client :ws [opts callback]
    (net/mk-client
     (assoc opts :type :tcp)
     (fn [tcp-server]
       (mk-websocket-client
        tcp-server opts
        (fn [ws-server]
          (callback (merge tcp-server ws-server)))))))

#_(defmethod net/mk-server :ws [opts callback]
    (net/mk-server
     (assoc opts :type :tcp)
     (fn [tcp-client]
       (mk-websocket-server
        tcp-client opts
        (fn [ws-client]
          (callback (merge tcp-client ws-client)))))))
