(ns clj-nproxy.test.proto
  "Protocol test utils."
  (:require [clojure.core.async :as a]
            [clj-nproxy.struct :as st]
            [clj-nproxy.proxy :as proxy])
  (:import [java.util.concurrent StructuredTaskScope StructuredTaskScope$Joiner]
           [java.io BufferedInputStream BufferedOutputStream]))

(defn ch->input-stream
  "Convert channel to input stream."
  [ch]
  (BufferedInputStream.
   (st/read-fn->input-stream #(a/<!! ch))))

(defn ch->output-stream
  "Convert channel to output stream."
  [ch]
  (BufferedOutputStream.
   (st/write-fn->output-stream
    (fn [b]
      (let [b (bytes b)]
        (when-not (zero? (alength b))
          (a/>!! ch b))))
    #(a/close! ch))))

(defn handshake
  "Run handshake on channel."
  [client-proc server-proc]
  (let [c->s (a/chan 1024)
        s->c (a/chan 1024)
        cis (ch->input-stream s->c)
        cos (ch->output-stream c->s)
        sis (ch->input-stream c->s)
        sos (ch->output-stream s->c)]
    (let [joiner (StructuredTaskScope$Joiner/allSuccessfulOrThrow)]
      (with-open [scope (StructuredTaskScope/open joiner)]
        (.fork scope ^Runnable #(client-proc cis cos))
        (.fork scope ^Runnable #(server-proc sis sos))
        (.join scope)))))

(defn proxy-handshake
  "Run proxy handhsake on channel."
  ([client-opts server-opts]
   (proxy-handshake client-opts server-opts "example.com" 80))
  ([client-opts server-opts host port]
   (let [vclient (volatile! nil)
         vserver (volatile! nil)]
     (handshake
      (fn [is os]
        (proxy/mk-client
         client-opts is os host port
         (fn [server]
           (vreset! vserver (dissoc server :input-stream :output-stream)))))
      (fn [is os]
        (proxy/mk-server
         server-opts is os
         (fn [client]
           (vreset! vclient (dissoc client :input-stream :output-stream))))))
     [@vclient @vserver])))
