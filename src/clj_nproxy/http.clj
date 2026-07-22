(ns clj-nproxy.http
  (:require [clj-nproxy.bytes :as b]
            [clj-nproxy.struct :as st]
            [clj-nproxy.net :as net])
  (:import [java.util Optional]
           [java.util.concurrent CompletableFuture BlockingQueue LinkedBlockingQueue]
           [java.time Duration]
           [java.io InputStream OutputStream]
           [java.nio ByteBuffer]
           [java.net URI ProxySelector]
           [java.net.http
            HttpHeaders
            HttpClient HttpClient$Builder HttpClient$Version HttpClient$Redirect
            HttpRequest HttpRequest$Builder HttpRequest$BodyPublisher HttpRequest$BodyPublishers
            HttpResponse HttpResponse$BodyHandler HttpResponse$BodyHandlers
            WebSocket WebSocket$Builder WebSocket$Listener]
           [clj_nproxy.java QueuedWebSocketListener QueuedWebSocketListener$Message]))

;;; http

(set! clojure.core/*warn-on-reflection* true)

(defn as-string
  ^String [s]
  (if (or (keyword? s) (symbol? s))
    (name s)
    (str s)))

(defn as-duration
  ^Duration [d]
  (if (instance? Duration d)
    d
    (Duration/ofMillis d)))

(defn as-uri
  ^URI [uri]
  (if (instance? URI uri)
    uri
    (URI/create uri)))

(def version-map
  {:http1.1 HttpClient$Version/HTTP_1_1
   :http2   HttpClient$Version/HTTP_2})

(defn as-version
  ^HttpClient$Version [v]
  (if (instance? HttpClient$Version v)
    v
    (get version-map v)))

(def redirect-map
  {:never  HttpClient$Redirect/NEVER
   :always HttpClient$Redirect/ALWAYS
   :normal HttpClient$Redirect/NORMAL})

(defn as-redirect
  ^HttpClient$Redirect [r]
  (if (instance? HttpClient$Redirect r)
    r
    (get redirect-map r)))

(def proxy-map
  {:no-proxy HttpClient$Builder/NO_PROXY})

(defn as-proxy
  ^ProxySelector [p]
  (if (instance? ProxySelector p)
    p
    (get proxy-map p)))

;;; body

(defn as-body-handler
  ^HttpResponse$BodyHandler [handler]
  (let [handler (or handler :discard)]
    (if (instance? HttpResponse$BodyHandler handler)
      handler
      (case handler
        :discard (HttpResponse$BodyHandlers/discarding)
        :byte-array (HttpResponse$BodyHandlers/ofByteArray)
        :string (HttpResponse$BodyHandlers/ofString)
        :input-stream (HttpResponse$BodyHandlers/ofInputStream)))))

(defprotocol BodyPublisherCoercions
  (^HttpRequest$BodyPublisher as-body-publisher [x]))

(extend-type HttpRequest$BodyPublisher
  BodyPublisherCoercions
  (as-body-publisher [b] b))

(extend-type nil
  BodyPublisherCoercions
  (as-body-publisher [_] (HttpRequest$BodyPublishers/noBody)))

(extend-type String
  BodyPublisherCoercions
  (as-body-publisher [s] (HttpRequest$BodyPublishers/ofString s)))

(extend-type byte/1
  BodyPublisherCoercions
  (as-body-publisher [b] (HttpRequest$BodyPublishers/ofByteArray b)))

(extend-type InputStream
  BodyPublisherCoercions
  (as-body-publisher [is] (HttpRequest$BodyPublishers/ofInputStream is)))

;;; headers

(defn headers-get
  ^String [^HttpHeaders headers key]
  (let [^Optional opt-val (.firstValue headers (as-string key))]
    (.orElse opt-val nil)))

(defn headers->map
  [^HttpHeaders headers]
  (->> (.map headers)
       (map
        (fn [[key vals]]
          (let [vals (if (= 1 (count vals))
                       (first vals)
                       (vec vals))]
            [key vals])))
       (into {})))

(defn flatten-headers-map
  [headers]
  (->> headers
       (mapcat
        (fn [[key vals]]
          (let [key (as-string key)]
            (->> (if (sequential? vals) vals [vals])
                 (map
                  (fn [val]
                    [key (as-string val)]))))))))

;;; client

(defn client-builder-apply-version
  ^HttpClient$Builder [^HttpClient$Builder builder {:keys [version]}]
  (cond-> builder
    (some? version) (.version (as-version version))))

(defn client-builder-apply-redirect
  ^HttpClient$Builder [^HttpClient$Builder builder {:keys [redirect]}]
  (cond-> builder
    (some? redirect) (.followRedirects (as-redirect redirect))))

(defn client-builder-apply-proxy
  ^HttpClient$Builder [^HttpClient$Builder builder {:keys [proxy]}]
  (cond-> builder
    (some? proxy) (.proxy (as-proxy proxy))))

(defn client-builder-apply-timeout
  ^HttpClient$Builder [^HttpClient$Builder builder {:keys [timeout client-timeout]}]
  (let [timeout (or client-timeout timeout)]
    (cond-> builder
      (some? timeout) (.connectTimeout (as-duration timeout)))))

(defn ->client
  ^HttpClient [opts]
  (-> (HttpClient/newBuilder)
      (client-builder-apply-version opts)
      (client-builder-apply-redirect opts)
      (client-builder-apply-proxy opts)
      (client-builder-apply-timeout opts)
      .build))

;;; request

(defn request-builder-apply-uri
  ^HttpRequest$Builder [^HttpRequest$Builder builder {:keys [uri]}]
  (.uri builder (as-uri uri)))

(defn request-builder-apply-method
  ^HttpRequest$Builder [^HttpRequest$Builder builder {:keys [method body] :or {method :get}}]
  (.method builder (as-string method) (as-body-publisher body)))

(defn request-builder-apply-headers
  ^HttpRequest$Builder [^HttpRequest$Builder builder {:keys [headers]}]
  (->> (flatten-headers-map headers)
       (reduce
        (fn [^HttpRequest$Builder builder [key val]]
          (.header builder key val))
        builder)))

(defn request-builder-apply-version
  ^HttpRequest$Builder [^HttpRequest$Builder builder {:keys [version]}]
  (cond-> builder
    (some? version) (.version (as-version version))))

(defn request-builder-apply-timeout
  ^HttpRequest$Builder [^HttpRequest$Builder builder {:keys [timeout http-timeout]}]
  (let [timeout (or http-timeout timeout)]
    (cond-> builder
      (some? timeout) (.timeout (as-duration timeout)))))

(defn ->request
  ^HttpRequest [opts]
  (-> (HttpRequest/newBuilder)
      (request-builder-apply-uri opts)
      (request-builder-apply-method opts)
      (request-builder-apply-headers opts)
      (request-builder-apply-version opts)
      (request-builder-apply-timeout opts)
      .build))

;;; response

(defn response->version
  ^HttpClient$Version [^HttpResponse response]
  (.version response))

(defn response->uri
  ^URI [^HttpResponse response]
  (.uri response))

(defn response->status
  ^long [^HttpResponse response]
  (.statusCode response))

(defn response->headers
  ^HttpHeaders [^HttpResponse response]
  (.headers response))

(defn response->body
  [^HttpResponse response]
  (.body response))

(defn response->map
  [^HttpResponse response]
  {:version (response->version response)
   :uri (response->uri response)
   :status (response->status response)
   :headers (response->headers response)
   :body (response->body response)})

(defn request
  (^HttpResponse [opts]
   (request (->client opts) opts))
  (^HttpResponse [^HttpClient client {:keys [as] :as opts}]
   (.send client (->request opts) (as-body-handler as))))

;;; websocket

(defn websocket-builder-apply-headers
  ^WebSocket$Builder [^WebSocket$Builder builder {:keys [headers]}]
  (->> (flatten-headers-map headers)
       (reduce
        (fn [^WebSocket$Builder builder [key val]]
          (.header builder key val))
        builder)))

(defn websocket-builder-apply-sub-protocols
  ^WebSocket$Builder [^WebSocket$Builder builder {:keys [sub-protocols]}]
  (cond-> builder
    (seq sub-protocols)
    (.subprotocols
     (-> sub-protocols first as-string)
     (->> sub-protocols rest (map as-string) object-array))))

(defn websocket-builder-apply-timeout
  ^WebSocket$Builder [^WebSocket$Builder builder {:keys [websocket-timeout timeout]}]
  (let [timeout (or websocket-timeout timeout)]
    (cond-> builder
      (some? timeout) (.connectTimeout (as-duration timeout)))))

(defn websocket-connect
  (^CompletableFuture [opts]
   (websocket-connect (->client opts) opts))
  (^CompletableFuture [^HttpClient client opts]
   (let [{:keys [uri ^WebSocket$Listener listener]} opts]
     (-> (.newWebSocketBuilder client)
         (websocket-builder-apply-headers opts)
         (websocket-builder-apply-sub-protocols opts)
         (websocket-builder-apply-timeout opts)
         (.buildAsync (as-uri uri) listener)))))

(defmethod net/mk-client :ws [{:keys [client uri] :as opts} callback]
  (let [^BlockingQueue queue (LinkedBlockingQueue. 4096)
        ^WebSocket$Listener listener (QueuedWebSocketListener. queue)
        ^HttpClient client (force client)
        ^WebSocket websocket @(websocket-connect client (assoc opts :listener listener))
        read-fn (fn []
                  (let [^QueuedWebSocketListener$Message message (.take queue)
                        data (.data message)]
                    (when (some? data)
                      (let [data (cond-> data (string? data) b/str->bytes)]
                        (if (zero? (b/length data))
                          (recur)
                          data)))))
        write-fn (fn [b]
                   @(.sendBinary websocket (ByteBuffer/wrap (bytes b)) true))
        close-fn (fn []
                   @(.sendClose websocket WebSocket/NORMAL_CLOSURE ""))]
    (with-open [is (st/read-fn->buffered-input-stream read-fn)
                os (st/write-fn->buffered-output-stream write-fn close-fn)]
      (callback {:websocket websocket :uri uri :input-stream is :output-stream os}))))

(defmethod net/edn->client-opts :ws [opts]
  (assoc opts :client (delay (->client opts))))
