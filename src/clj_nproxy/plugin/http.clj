(ns clj-nproxy.plugin.http
  (:require [clojure.string :as str]
            [clj-nproxy.struct :as st]
            [clj-nproxy.proxy :as proxy]))

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

^:rct/test
(comment
  (unpack-http "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: open")
  ;; => ["GET / HTTP/1.1" {"host" "example.com" "connection" "open"}]
  (pack-http "GET / HTTP/1.1" {"host" "example.com" "connection" "open"})
  ;; => "GET / HTTP/1.1\r\nhost: example.com\r\nconnection: open"
  )

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

^:rct/test
(comment
  (String. (st/pack st-http-req {})) ; => "GET / HTTP/1.1\r\n\r\n"
  (st/unpack st-http-req (.getBytes "GET / HTTP/1.1\r\n\r\n")) ; => {:method "GET" :path "/" :version "HTTP/1.1" :headers {}}
  )

(def hostport-re #"^([^:]+):(\d+)$")
(def bracketed-hostport-re #"^\[([^\[\]]+)\]:(\d+)$")

(defn unpack-hostport
  "Unpack host port."
  [^String s]
  (let [re (if (= \[ (first s)) bracketed-hostport-re hostport-re)]
    (if-let [matches (re-matches re s)]
      (let [host (get matches 1)
            port (parse-long (get matches 2))]
        [host port])
      (throw (ex-info "invalid hostport" {:reason ::invalid-hostport :hostport s})))))

(defn pack-hostport
  "Pack host port."
  ^String [host port]
  (let [fmt (if (str/index-of host ":") "[%s]:%d" "%s:%d")]
    (format fmt host port)))

^:rct/test
(comment
  (unpack-hostport "example.com:80") ; => ["example.com" 80]
  (unpack-hostport "[2000::1]:443") ; => ["2000::1" 443]
  (pack-hostport "example.com" 80) ; => "example.com:80"
  (pack-hostport "2000::1" 443) ; => "[2000::1]:443"
  )

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

(defmethod proxy/mk-client :http [{:keys [headers]} server host port callback]
  (let [{is :input-stream os :output-stream} server
        hostport (pack-hostport host port)
        headers (merge {"host" hostport} headers)]
    (st/write-struct st-http-req os {:method "CONNECT" :path hostport :headers headers})
    (st/flush os)
    (let [resp (-> (st/read-struct st-http-resp is) valid-version (valid-status "200"))]
      (callback {:http-resp resp :input-stream is :output-stream os}))))

;; limited: only accept connect method with explicit port

(defmethod proxy/mk-server :http [{:keys [headers]} client callback]
  (let [{is :input-stream os :output-stream} client
        {:keys [path] :as req} (-> (st/read-struct st-http-req is) valid-version (valid-method "connect"))]
    (let [[host port] (unpack-hostport path)
          headers (merge {"connection" "close"} headers)]
      (st/write-struct st-http-resp os {:headers headers})
      (st/flush os)
      (callback {:http-req req :input-stream is :output-stream os :host host :port port}))))
