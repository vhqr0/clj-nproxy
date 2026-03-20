(ns clj-nproxy.plugin.ws-test
  (:require [clojure.test :refer [deftest is]]
            [clj-nproxy.bytes :as b]
            [clj-nproxy.struct :as st]
            [clj-nproxy.proxy :as proxy]
            [clj-nproxy.plugin.ws :as ws]))

(deftest ws-test
  (is (some? (st/sim-conn
              (fn [server]
                (ws/mk-client
                 server nil
                 (fn [server]
                   (proxy/mk-client
                    server {:type :http} "example.com" 80
                    (fn [{is :input-stream}]
                      (st/read-bytes is 1))))))
              (fn [client]
                (ws/mk-server
                 client nil
                 (fn [client]
                   (proxy/mk-server
                    client {:type :http}
                    (fn [{os :output-stream}]
                      (st/write os (b/rand 1))
                      (st/close os))))))))))
