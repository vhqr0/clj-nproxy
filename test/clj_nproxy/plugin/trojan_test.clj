(ns clj-nproxy.plugin.trojan-test
  (:require [clojure.test :refer [deftest is]]
            [clj-nproxy.test.proto :as proto]
            [clj-nproxy.proxy :as proxy]
            clj-nproxy.plugin.trojan))

(deftest trojan-test
  (is (= [{:host "example.com" :port 80} {}]
         (proto/proxy-handshake
          (proxy/edn->client-opts {:type :trojan :password "hello"})
          (proxy/edn->server-opts {:type :trojan :password "hello"})))))
