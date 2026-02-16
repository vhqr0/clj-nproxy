(ns clj-nproxy.plugin.http-test
  (:require [clojure.test :refer [deftest is]]
            [clj-nproxy.proxy :as proxy]
            clj-nproxy.plugin.http))

(deftest http-test
  (is (some? (proxy/sim-conn {:type :http} {:type :http} "example.com" 80 (fn [_]) (fn [_])))))
