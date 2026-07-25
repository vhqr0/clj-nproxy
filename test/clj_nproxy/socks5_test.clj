(ns clj-nproxy.socks5-test
  (:require [clojure.test :refer [deftest is]]
            [clj-nproxy.struct :as st]
            [clj-nproxy.net :as net]
            [clj-nproxy.socks5 :as socks5]))

(deftest trojan-auth-test
  (is (= "ea09ae9cc6768c50fcee903ed054556e5bfc8347907f12598aa24193"
         (socks5/trojan-auth "hello"))))

(deftest socks5-test
  (is (some? (st/sim-conn
              (fn [server]
                (net/mk-proxy-client server {:type :socks5} "example.com" 80 (fn [_])))
              (fn [client]
                (net/mk-proxy-server client {:type :socks5} (fn [_]))))))
  (is (some? (st/sim-conn
              (fn [server]
                (net/mk-proxy-client
                 server
                 {:type :socks5 :auth {:username "user" :password "pwd"}}
                 "example.com" 80 (fn [_])))
              (fn [client]
                (net/mk-proxy-server
                 client
                 {:type :socks5 :auth {:username "user" :password "pwd"}}
                 (fn [_])))))))

(deftest trojan-test
  (is (some? (st/sim-conn
              (fn [server]
                (net/mk-proxy-client
                 server
                 (net/edn->proxy-client-opts {:type :trojan :password "hello"})
                 "example.com" 80 (fn [_])))
              (fn [client]
                (net/mk-proxy-server
                 client
                 (net/edn->proxy-server-opts {:type :trojan :password "hello"})
                 (fn [_])))))))
