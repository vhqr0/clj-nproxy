(ns clj-nproxy.plugin.socks5-test
  (:require [clojure.test :refer [deftest is]]
            [clj-nproxy.test.proto :as proto]
            clj-nproxy.plugin.socks5))

(deftest socks5-test
  (is (= [{:host "example.com" :port 80} {}]
         (proto/proxy-handshake {:type :socks5} {:type :socks5}))))
