(ns clj-nproxy.plugin.socks5-test
  (:require [clojure.test :refer [deftest is]]
            [clj-nproxy.proxy :as proxy]
            clj-nproxy.plugin.socks5))

(deftest socks5-test
  (is (some? (proxy/sim-conn {:type :socks5} {:type :socks5} "example.com" 80 (fn [_]) (fn [_])))))
