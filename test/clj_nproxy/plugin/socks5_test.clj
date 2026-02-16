(ns clj-nproxy.plugin.socks5-test
  (:require [clojure.test :refer [deftest is]]
            [clj-nproxy.struct :as st]
            [clj-nproxy.proxy :as proxy]
            clj-nproxy.plugin.socks5))

(deftest socks5-test
  (is (some? (st/sim-conn
              (fn [server]
                (proxy/mk-client {:type :socks5} server "example.com" 80 (fn [_])))
              (fn [client]
                (proxy/mk-server {:type :socks5} client (fn [_])))))))
