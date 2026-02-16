(ns clj-nproxy.plugin.trojan-test
  (:require [clojure.test :refer [deftest is]]
            [clj-nproxy.struct :as st]
            [clj-nproxy.proxy :as proxy]
            clj-nproxy.plugin.trojan))

(deftest trojan-test
  (is (some? (st/sim-conn
              (fn [server]
                (proxy/mk-client
                 (proxy/edn->client-opts {:type :trojan :password "hello"})
                 server "example.com" 80 (fn [_])))
              (fn [client]
                (proxy/mk-server
                 (proxy/edn->server-opts {:type :trojan :password "hello"})
                 client (fn [_])))))))

