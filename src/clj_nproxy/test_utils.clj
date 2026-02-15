(ns clj-nproxy.test-utils
  "Test utils."
  (:require [clj-nproxy.struct :as st]
            [clj-nproxy.proxy :as proxy])
  (:import [java.util.concurrent StructuredTaskScope StructuredTaskScope$Joiner]
           [java.io PipedInputStream PipedOutputStream]))

(defn handshake
  "Run handshake on internal pipe stream."
  [client-proc server-proc]
  (with-open [cis (PipedInputStream.)
              cos (PipedOutputStream.)
              sis (PipedInputStream.)
              sos (PipedOutputStream.)]
    (.connect cos sis)
    (.connect sos cis)
    (let [joiner (StructuredTaskScope$Joiner/allSuccessfulOrThrow)]
      (with-open [scope (StructuredTaskScope/open joiner)]
        (.fork scope ^Runnable #(client-proc {:input-stream cis :output-stream cos}))
        (.fork scope ^Runnable #(server-proc {:input-stream sis :output-stream sos}))
        (.join scope)))))

(defn proxy-handshake
  "Run proxy handhsake on internal pipe stream."
  [client-opts server-opts host port client-proc server-proc]
  (handshake
   (fn [{is :input-stream os :output-stream}]
     (proxy/mk-client
      client-opts is os host port
      (fn [server]
        (client-proc server))))
   (fn [{is :input-stream os :output-stream}]
     (proxy/mk-server
      server-opts is os
      (fn [client]
        (server-proc client))))))
