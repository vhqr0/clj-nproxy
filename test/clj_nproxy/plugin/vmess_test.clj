(ns clj-nproxy.plugin.vmess-test
  (:require [clojure.test :refer [deftest is]]
            [clj-nproxy.bytes :as b]
            [clj-nproxy.struct :as st]
            [clj-nproxy.proxy :as proxy]
            clj-nproxy.plugin.vmess)
  (:import [java.io InputStream OutputStream]))

(set! clojure.core/*warn-on-reflection* true)

(deftest vmess-test
  (is (some? (let [uuid (str (random-uuid))]
               (st/sim-conn
                (fn [server]
                  (proxy/mk-client
                   (proxy/edn->client-opts {:type :vmess :uuid uuid})
                   server "example.com" 80
                   (fn [{^InputStream is :input-stream ^OutputStream os :output-stream}]
                     (.write os (bytes (b/rand 4)))
                     (.flush os)
                     (st/read-bytes is 4))))
                (fn [client]
                  (proxy/mk-server
                   (proxy/edn->server-opts {:type :vmess :uuid uuid})
                   client
                   (fn [{^InputStream is :input-stream ^OutputStream os :output-stream}]
                     (let [b (bytes (st/read-bytes is 4))]
                       (.write os b)
                       (.flush os))))))))))
