(ns clj-nproxy.plugin.ws
  (:require [clojure.core.async :as a]
            [clj-nproxy.struct :as st]
            [clj-nproxy.net :as net])
  (:import [java.io BufferedInputStream BufferedOutputStream]
           [java.nio ByteBuffer]
           [java.net URI]
           [java.net.http HttpClient WebSocket WebSocket$Listener]))

(set! clojure.core/*warn-on-reflection* true)

(defn buffer->bytes
  "Convert byte buffer to bytes."
  ^bytes [^ByteBuffer buf]
  (let [ba (byte-array (.remaining buf))]
    (.get buf ba)
    ba))

(defn ch->listener
  "Convert channel to websocket listener."
  ^WebSocket$Listener [ch]
  (reify WebSocket$Listener
    (onText [_ _ws _s _last?]
      (throw (st/data-error))
      nil)
    (onBinary [_ ws buf _last?]
      (when-not (zero? (.remaining buf))
        (a/>!! ch (buffer->bytes buf)))
      (.request ^WebSocket ws 1)
      nil)
    (onClose [_ _ws _status _reason]
      (a/close! ch)
      nil)))

(def ^:dynamic *http-client* (delay (HttpClient/newHttpClient)))

(defmethod net/mk-client :ws [{:keys [uri]} callback]
  (let [ch (a/chan 1024)
        ^HttpClient client (force *http-client*)
        ^WebSocket ws @(.buildAsync
                        (.newWebSocketBuilder client)
                        (URI/create uri)
                        (ch->listener ch))
        is (BufferedInputStream.
            (st/read-fn->input-stream #(a/<!! ch)))
        os (BufferedOutputStream.
            (st/write-fn->output-stream
             (fn [b] @(.sendBinary ws (ByteBuffer/wrap (bytes b)) true))
             (fn [] @(.sendClose ws WebSocket/NORMAL_CLOSURE ""))))]
    (callback
     {:peer {:ws-uri uri}
      :input-stream is
      :output-stream os})))
