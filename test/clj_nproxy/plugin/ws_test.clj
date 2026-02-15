(ns clj-nproxy.plugin.ws-test
  (:require [clojure.test :refer [deftest is]]
            [clj-nproxy.test-utils :as utils]
            [clj-nproxy.proxy :as proxy]
            [clj-nproxy.plugin.ws :as ws]))

(deftest ws-test
  (is (some? (utils/handshake
              (fn [server]
                (ws/mk-client
                 nil server
                 (fn [server]
                   (proxy/mk-client
                    {:type :http} server "example.com" 80
                    (fn [_])))))
              (fn [client]
                (ws/mk-server
                 nil client
                 (fn [client]
                   (proxy/mk-server
                    {:type :http} client
                    (fn [_])))))))))
