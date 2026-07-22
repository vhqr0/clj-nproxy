(ns clj-nproxy.experiment.http-test
  (:require [clojure.test :refer [deftest is]]
            [clj-nproxy.bytes :as b]
            [clj-nproxy.struct :as st]
            [clj-nproxy.proxy :as proxy]
            [clj-nproxy.experiment.http :as http]))

(deftest header-struct-test
  (is (= ["GET / HTTP/1.1" {"host" "example.com" "connection" "open"}]
         (http/unpack-http "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: open")))
  (is (= "GET / HTTP/1.1\r\nhost: example.com\r\nconnection: open"
         (http/pack-http "GET / HTTP/1.1" {"host" "example.com" "connection" "open"})))
  (is (= "GET / HTTP/1.1\r\n\r\n"
         (b/bytes->str (st/pack http/st-http-req {}))))
  (is (= {:method "GET" :path "/" :version "HTTP/1.1" :headers {}}
         (st/unpack http/st-http-req (b/str->bytes "GET / HTTP/1.1\r\n\r\n")))))

(deftest hostport-struct-test
  (is (= ["example.com" 80]
         (http/unpack-hostport "example.com:80")))
  (is (= ["2000::1" 443]
         (http/unpack-hostport "[2000::1]:443")))
  (is (= ["example.com" nil]
         (http/unpack-hostport "example.com")))
  (is (= ["2000::1" nil]
         (http/unpack-hostport "[2000::1]")))
  (is (= "example.com:80"
         (http/pack-hostport "example.com" 80)))
  (is (= "[2000::1]:443"
         (http/pack-hostport "2000::1" 443))))

(deftest ws-accept-test
  (is (= "ICX+Yqv66kxgM0FcWaLWlFLwTAI="
         (http/websocket-key->accept (b/bytes->base64 (byte-array 16))))))

(deftest http-test
  (is (some? (st/sim-conn
              (fn [server]
                (proxy/mk-client server {:type :http} "example.com" 80 (fn [_])))
              (fn [client]
                (proxy/mk-server client {:type :http} (fn [_])))))))

(deftest ws-test
  (is (some? (st/sim-conn
              (fn [server]
                (http/mk-websocket-client
                 server nil
                 (fn [server]
                   (proxy/mk-client
                    server {:type :http} "example.com" 80
                    (fn [{is :input-stream}]
                      (st/read-bytes is 1))))))
              (fn [client]
                (http/mk-websocket-server
                 client nil
                 (fn [client]
                   (proxy/mk-server
                    client {:type :http}
                    (fn [{os :output-stream}]
                      (st/write os (b/rand 1))
                      (st/close os))))))))))
