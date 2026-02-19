(ns clj-nproxy.plugin.vmess-test
  (:require [clojure.test :refer [deftest is]]
            [clj-nproxy.bytes :as b]
            [clj-nproxy.struct :as st]
            [clj-nproxy.proxy :as proxy]
            clj-nproxy.plugin.vmess))

(set! clojure.core/*warn-on-reflection* true)

(defn sim-vmess
  [opts]
  (let [uuid (str (random-uuid))]
    (st/sim-conn
     (fn [server]
       (proxy/mk-client
        (proxy/edn->client-opts (merge {:type :vmess :uuid uuid} opts))
        server "example.com" 80
        (fn [{is :input-stream os :output-stream}]
          (st/write os (b/rand 4))
          (st/flush os)
          (st/read-bytes is 4))))
     (fn [client]
       (proxy/mk-server
        (proxy/edn->server-opts {:type :vmess :uuid uuid})
        client
        (fn [{is :input-stream os :output-stream}]
          (let [b (st/read-bytes is 4)]
            (st/write os b)
            (st/flush os))))))))

(deftest vmess-test
  (is (some? (sim-vmess {})))
  (is (some? (sim-vmess {:sec :chacha20poly1305})))
  (is (some? (sim-vmess {:use-mask? false :use-padding? false}))))
