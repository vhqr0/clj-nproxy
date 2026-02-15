(ns clj-nproxy.plugin.http-test
  (:require [clojure.test :refer [deftest is]]
            [clj-nproxy.test-utils :as utils]
            clj-nproxy.plugin.http))

(deftest http-test
  (is (some? (utils/proxy-handshake
              {:type :http} {:type :http} "example.com" 80 (fn [_]) (fn [_])))))
