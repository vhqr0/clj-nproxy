(ns clj-nproxy.plugin.http
  (:require [clojure.string :as str]
            [clj-nproxy.struct :as st]
            [clj-nproxy.proxy :as proxy])
  (:import [java.io InputStream OutputStream]))

(defn unpack-http
  "Unpack text (before \r\n\r\n) to http."
  [^String s]
  (let [lines (str/split s #"\r\n" -1)
        first-line (first lines)
        headers (->> (rest lines)
                     (map
                      (fn [line]
                        (let [kv (str/split line #":" 2)]
                          (if-not (= 2 (count kv))
                            (throw (st/data-error))
                            (let [[k v] kv]
                              [(str/lower-case (str/trim k)) (str/trim v)])))))
                     (into {}))]
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

(defn unpack-http-req
  "Unpack http request."
  [^String s]
  (let [[first-line headers] (unpack-http s)
        sp (str/split first-line #"\s+" 3)]
    (if-not (= 3 (count sp))
      (throw (st/data-error))
      (let [[method path version] sp]
        {:method method
         :path path
         :version version
         :headers headers}))))

(defn pack-http-req
  "Pack http request."
  ^String [{:keys [method path version headers]
            :or {method "GET" path "/" version "HTTP/1.1"}}]
  (pack-http (format "%s %s %s" method path version) headers))

(defn unpack-http-resp
  "Unpack http response."
  [^String s]
  (let [[first-line headers] (unpack-http s)
        sp (str/split first-line #"\s+" 3)]
    (if-not (= 3 (count sp))
      (throw (st/data-error))
      (let [[version status reason] sp]
        {:version version
         :status status
         :reason reason
         :headers headers}))))

(defn pack-http-resp
  "Pack http response."
  ^String [{:keys [version status reason headers]
            :or {version "HTTP/1.1" status "200" reason "OK"}}]
  (pack-http (format "%s %s %s" version status reason) headers))

(def st-http-req
  (-> (st/->st-line "\r\n\r\n")
      (st/wrap unpack-http-req pack-http-req)))

(def st-http-resp
  (-> (st/->st-line "\r\n\r\n")
      (st/wrap unpack-http-resp pack-http-resp)))

^:rct/test
(comment
  (String. (st/pack st-http-req {})) ; => "GET / HTTP/1.1\r\n\r\n"
  (st/unpack st-http-req (.getBytes "GET / HTTP/1.1\r\n\r\n")) ; => {:method "GET", :path "/", :version "HTTP/1.1", :headers {}}
  )

(def hostport-re #"^([^:]+):(.+)$")
(def bracketed-hostport-re #"^\[([^\[\]]+)\]:(.+)$")

(defn unpack-hostport
  "Unpack host port."
  [^String s]
  (let [re (if (= \[ (first s)) bracketed-hostport-re hostport-re)]
    (if-let [matches (re-matches re s)]
      (let [host (get matches 1)
            port (parse-long (get matches 2))]
        [host port])
      (throw (st/data-error)))))

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

(defmethod proxy/mk-client :http [{:keys [headers]} ^InputStream is ^OutputStream os host port callback]
  (let [hostport (pack-hostport host port)
        headers (merge {"host" hostport} headers)]
    (st/write-struct st-http-req os {:method "CONNECT" :path hostport :headers headers})
    (.flush os)
    (let [{:keys [status] :as resp} (st/read-struct st-http-resp is)]
      (if (= status "200")
        (callback {:http-resp resp :input-stream is :output-stream os})
        (throw (st/data-error))))))

(defmethod proxy/mk-server :http [{:keys [headers]} ^InputStream is ^OutputStream os callback]
  (let [{:keys [method path] :as req} (st/read-struct st-http-req is)]
    (if (= "connect" (str/lower-case method))
      (let [[host port] (unpack-hostport path)
            headers (merge {"connection" "close"} headers)]
        (st/write-struct st-http-resp os {:headers headers})
        (.flush os)
        (callback {:http-req req :input-stream is :output-stream os :host host :port port}))
      (throw (st/data-error)))))
