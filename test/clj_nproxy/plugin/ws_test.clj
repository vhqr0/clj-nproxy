(ns clj-nproxy.plugin.ws-test
  (:require [clojure.test :refer [deftest is]]
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
                    (fn [{is :input-stream os :output-stream}]
                      (st/close os)
                      (st/read-eof is))))))
              (fn [client]
                (ws/mk-server
                 client nil
                 (fn [client]
                   (proxy/mk-server
                    client {:type :http}
                    (fn [{is :input-stream os :output-stream}]
                      (st/close os)
                      (st/read-eof is))))))))))
