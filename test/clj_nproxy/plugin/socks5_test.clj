(ns clj-nproxy.plugin.socks5-test
  (:require [clojure.test :refer [deftest is]]
            [clj-nproxy.test-utils :as utils]
            clj-nproxy.plugin.socks5))

(deftest socks5-test
  (is (some? (utils/proxy-handshake
              {:type :socks5} {:type :socks5} "example.com" 80 (fn [_]) (fn [_])))))
