(ns clj-nproxy.plugin.ws-test
  (:require [clojure.test :refer [deftest is]]
            [clj-nproxy.test.proto :as proto]
            [clj-nproxy.proxy :as proxy]
            [clj-nproxy.plugin.ws :as ws]))

(deftest ws-test
  (is (= [{:http-req {:method "CONNECT"
                      :path "example.com:80"
                      :version "HTTP/1.1"
                      :headers {"host" "example.com:80"}}
           :host "example.com"
           :port 80}
          {:http-resp {:version "HTTP/1.1"
                       :status "200"
                       :reason "OK"
                       :headers {"connection" "close"}}}]
         (let [vclient (volatile! nil)
               vserver (volatile! nil)]
           (proto/handshake
            (fn [{is :input-stream os :output-stream}]
              (ws/mk-client
               nil is os
               (fn [{is :input-stream os :output-stream}]
                 (proxy/mk-client
                  {:type :http} is os "example.com" 80
                  (fn [server]
                    (vreset! vserver (dissoc server :input-stream :output-stream)))))))
            (fn [{is :input-stream os :output-stream}]
              (ws/mk-server
               nil is os
               (fn [{is :input-stream os :output-stream}]
                 (proxy/mk-server
                  {:type :http} is os
                  (fn [client]
                    (vreset! vclient (dissoc client :input-stream :output-stream))))))))
           [@vclient @vserver]))))
