(ns clj-nproxy.plugin.tls13
  "TLS 1.3 impl."
  (:require [clj-nproxy.bytes :as b]
            [clj-nproxy.struct :as st]
            [clj-nproxy.plugin.tls13.struct :as tls13-st]
            [clj-nproxy.plugin.tls13.context :as tls13-ctx])
  (:import [java.io BufferedInputStream BufferedOutputStream]))

(set! clojure.core/*warn-on-reflection* true)

(defn handshake
  "Do handshake on stream, return new context."
  [{is :input-stream os :output-stream} context]
  (loop [context context]
    (let [{:keys [stage send-bytes]} context]
      (if (seq send-bytes)
        (do
          (run! (partial st/write os) send-bytes)
          (st/flush os)
          (recur (dissoc context :send-bytes)))
        (if (= stage :connected)
          context
          (let [{:keys [type content]} (st/read-struct tls13-st/st-record is)]
            (recur (tls13-ctx/recv-record context type content))))))))

(defn wrap-input-stream
  "Wrap input stream."
  [is acontext]
  (let [read-fn (fn []
                  (let [{:keys [recv-bytes read-close?]} @acontext]
                    (if (seq recv-bytes)
                      (do
                        (swap! acontext update :recv-bytes #(vec (drop (count recv-bytes) %)))
                        (let [b (apply b/cat recv-bytes)]
                          (if-not (zero? (b/length b))
                            b
                            (recur))))
                      (when-not read-close?
                        (let [{:keys [type content]} (st/read-struct tls13-st/st-record is)]
                          (swap! acontext tls13-ctx/recv-record type content)
                          (recur))))))]
    (BufferedInputStream. (st/read-fn->input-stream read-fn #(st/close is)))))

(defn wrap-output-stream
  "Wrap output stream."
  [os acontext]
  (let [write-fn (fn [b]
                   (when-not (zero? (b/length b))
                     (when (:key-update? @acontext)
                       (swap! acontext tls13-ctx/send-key-update))
                     (swap! acontext tls13-ctx/send-data b)
                     (let [{:keys [send-bytes]} @acontext]
                       (when (seq send-bytes)
                         (swap! acontext update :send-bytes #(vec (drop (count send-bytes) %)))
                         (run! (partial st/write os) send-bytes)
                         (st/flush os)))))
        close-fn (fn []
                   (swap! acontext tls13-ctx/send-close-notify)
                   (let [{:keys [send-bytes]} @acontext]
                     (when (seq send-bytes)
                       (swap! acontext update :send-bytes #(vec (drop (count send-bytes) %)))
                       (run! (partial st/write os) send-bytes)
                       (st/flush os))
                     (st/close os)))]
    (BufferedOutputStream. (st/write-fn->output-stream write-fn close-fn))))

(defn wrap-stream
  "Wrap tls13 on stream."
  ([stream context]
   (wrap-stream stream context identity))
  ([{is :input-stream os :output-stream :as stream} context handshake-callback]
   (let [context (handshake stream context)
         ;; valid server name, certificate list, etc
         context (handshake-callback context)
         acontext (atom context)]
     {:acontext acontext
      :input-stream (wrap-input-stream is acontext)
      :output-stream (wrap-output-stream os acontext)})))
