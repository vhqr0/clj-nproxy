(ns clj-nproxy.plugin.trojan-test
  (:require [clojure.test :refer [deftest is]]
            [clj-nproxy.proxy :as proxy]
            clj-nproxy.plugin.trojan))

(deftest trojan-test
  (is (some? (proxy/sim-conn
              (proxy/edn->client-opts {:type :trojan :password "hello"})
              (proxy/edn->server-opts {:type :trojan :password "hello"})
              "example.com" 80 (fn [_]) (fn [_])))))
