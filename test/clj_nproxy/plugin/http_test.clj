(ns clj-nproxy.plugin.http-test
  (:require [clojure.test :refer [deftest is]]
            [clj-nproxy.struct :as st]
            [clj-nproxy.proxy :as proxy]
            clj-nproxy.plugin.http))

(deftest http-test
  (is (some? (st/sim-conn
              (fn [server]
                (proxy/mk-client {:type :http} server "example.com" 80 (fn [_])))
              (fn [client]
                (proxy/mk-server {:type :http} client (fn [_])))))))
