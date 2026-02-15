(ns clj-nproxy.plugin.trojan-test
  (:require [clojure.test :refer [deftest is]]
            [clj-nproxy.test-utils :as utils]
            [clj-nproxy.proxy :as proxy]
            clj-nproxy.plugin.trojan))

(deftest trojan-test
  (is (some? (utils/proxy-handshake
              (proxy/edn->client-opts {:type :trojan :password "hello"})
              (proxy/edn->server-opts {:type :trojan :password "hello"})
              "example.com" 80 (fn [_]) (fn [_])))))
