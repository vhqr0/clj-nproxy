(ns clj-nproxy.tool.vsub-test
  (:require [clojure.test :refer [deftest is]]
            [clj-nproxy.tool.vsub :as vsub]))

(deftest net-opts-test
  (is (= {:type :tcp :host "foo" :port 80}
         (vsub/node->net-opts {"net" "tcp", "add" "foo", "port" "80"})))
  (is (= {:type :tcp :host "foo" :port 443 :ssl? true :ssl-params {:sni ["bar"]}}
         (vsub/node->net-opts {"net" "tcp", "add" "foo", "port" "443", "tls" "tls", "host" "bar"})))
  (is (= {:type :tcp :host "foo" :port 80 :ssl? true :ssl-params {:sni ["foo"] :alpn ["h2"]}}
         (vsub/node->net-opts {"net" "tcp", "add" "foo", "port" "80", "tls" "tls", "alpn" "h2"})))
  (is (= {:type :ws :uri "wss://foo:80/" :headers {"host" "bar"}}
         (vsub/node->net-opts {"net" "ws", "add" "foo", "port" "80", "tls" "tls", "host" "bar"})))
  (is (= {:type :ws :uri "ws://foo:80/ray" :headers {"host" "foo"}}
         (vsub/node->net-opts {"net" "ws", "add" "foo", "port" "80", "path" "/ray"}))))
