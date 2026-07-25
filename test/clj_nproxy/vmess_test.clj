(ns clj-nproxy.vmess-test
  (:require [clojure.test :refer [deftest is]]
            [clj-nproxy.bytes :as b]
            [clj-nproxy.struct :as st]
            [clj-nproxy.net :as net]
            [clj-nproxy.vmess :as vmess]))

(deftest checksum-test
  (is (= "3610a686"
         (-> "hello" b/str->bytes vmess/crc32 b/bytes->hex)))
  (is (= "4f9f2cab"
         (-> "hello" b/str->bytes vmess/fnv1a b/bytes->hex))))

(deftest shake128-test
  (let [test-read-fn (vmess/shake128-read-fn (b/str->bytes "hello"))]
    (is (= "8eb4b6a9"
           (b/bytes->hex (test-read-fn 4))))
    (is (= "32f28033"
           (b/bytes->hex (test-read-fn 4))))))

(defn sim-vmess
  [opts]
  (let [uuid (str (random-uuid))]
    (st/sim-conn
     (fn [server]
       (net/mk-proxy-client
        server
        (net/edn->proxy-client-opts (merge {:type :vmess :uuid uuid} opts))
        "example.com" 80
        (fn [{is :input-stream os :output-stream}]
          (st/write os (b/rand 4))
          (st/flush os)
          (st/read-bytes is 4)
          (st/close os)
          (st/read-eof is))))
     (fn [client]
       (net/mk-proxy-server
        client
        (net/edn->proxy-server-opts {:type :vmess :uuid uuid})
        (fn [{is :input-stream os :output-stream}]
          (let [b (st/read-bytes is 4)]
            (st/write os b)
            (st/flush os)
            (st/close os)
            (st/read-eof is))))))))

(deftest vmess-test
  (is (some? (sim-vmess {})))
  (is (some? (sim-vmess {:sec :chacha20poly1305})))
  (is (some? (sim-vmess {:use-mask? false :use-padding? false}))))
