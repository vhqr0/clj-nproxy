(ns clj-nproxy.plugin.http-test
  (:require [clojure.test :refer [deftest is]]
            [clj-nproxy.test.proto :as proto]
            clj-nproxy.plugin.http))

(deftest http-test
  (is (= [{:http-req {:method "CONNECT"
                      :path "example.com:80"
                      :version "HTTP/1.1"
                      :headers {"host" "example.com:80"}}
           :host "example.com" :port 80}
          {:http-resp {:version "HTTP/1.1"
                       :status "200"
                       :reason "OK"
                       :headers {"connection" "close"}}}]
         (proto/proxy-handshake {:type :http} {:type :http}))))
