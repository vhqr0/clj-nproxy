(ns clj-nproxy.plugin.ws
  (:require [clojure.core.async :as a]
            [clj-nproxy.struct :as st]
            [clj-nproxy.net :as net])
  (:import [java.io BufferedInputStream BufferedOutputStream]
           [java.nio ByteBuffer]
           [java.net URI]
           [java.net.http HttpClient WebSocket WebSocket$Builder WebSocket$Listener]))

(set! clojure.core/*warn-on-reflection* true)

;; ugly hack: allow rewrite host header
(System/setProperty "jdk.httpclient.allowRestrictedHeaders" "host")

(defn ch->listener
  "Convert channel to websocket listener."
  ^WebSocket$Listener [ch]
  (reify WebSocket$Listener
    (onText [_ _ws _s _last?]
      (throw (st/data-error))
      nil)
    (onBinary [_ ws buf _last?]
      (let [^ByteBuffer buf buf]
        (when-not (zero? (.remaining buf))
          (let [ba (byte-array (.remaining buf))]
            (.get buf ba)
            (a/>!! ch ba))))
      (.request ^WebSocket ws 1)
      nil)
    (onClose [_ _ws _status _reason]
      (a/close! ch)
      nil)))

(defn websocket-builder-apply-headers
  "Apply headers on websocket builder."
  ^WebSocket$Builder [^WebSocket$Builder builder headers]
  (->> headers
       (reduce
        (fn [^WebSocket$Builder builder [k v]]
          (.header builder (str k) (str v)))
        builder)))

(defn websocket-builder-apply-subprotocols
  "Apply subprotocols on websocket builder."
  ^WebSocket$Builder [^WebSocket$Builder builder subprotocols]
  (let [proto (first subprotocols)
        protos (object-array (rest subprotocols))]
    (.subprotocols builder proto protos)))

(defn mk-websocket-builder
  "Make websocket builder."
  ^WebSocket$Builder [^HttpClient client {:keys [headers subprotocols]}]
  (cond-> (.newWebSocketBuilder client)
    (some? headers) (websocket-builder-apply-headers headers)
    (some? subprotocols) (websocket-builder-apply-subprotocols subprotocols)))

(defmethod net/mk-client :ws [{:keys [client uri] :as opts} callback]
  (let [ch (a/chan 1024)
        ^WebSocket$Builder builder (mk-websocket-builder client opts)
        ^WebSocket ws @(.buildAsync builder (URI/create uri) (ch->listener ch))
        is (BufferedInputStream.
            (st/read-fn->input-stream #(a/<!! ch)))
        os (BufferedOutputStream.
            (st/write-fn->output-stream
             (fn [b]
               (let [b (bytes b)]
                 (when-not (zero? (alength b))
                   @(.sendBinary ws (ByteBuffer/wrap b) true))))
             (fn [] @(.sendClose ws WebSocket/NORMAL_CLOSURE ""))))]
    (callback
     {:peer {:ws-uri uri}
      :input-stream is
      :output-stream os})))

(defmethod net/edn->client-opts :ws [opts]
  (assoc opts :client (HttpClient/newHttpClient)))
