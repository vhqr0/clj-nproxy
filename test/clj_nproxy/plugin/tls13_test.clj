(ns clj-nproxy.plugin.tls13-test
  (:require [clojure.test :refer [deftest testing is]]
            [clojure.java.io :as io]
            [clj-nproxy.bytes :as b]
            [clj-nproxy.struct :as st]
            [clj-nproxy.crypto.keystore :as ks]
            [clj-nproxy.plugin.tls13 :as tls13]
            [clj-nproxy.plugin.tls13.struct :as tls13-st]
            [clj-nproxy.plugin.tls13.context :as tls13-ctx]))

(defn read-resource
  [resource]
  (with-open [is (io/input-stream (io/resource resource))]
    (st/read-all is)))

(defonce cert (delay (ks/bytes->cert (read-resource "resources/cert.der"))))
(defonce pri (delay (ks/bytes->pri "Ed25519" (read-resource "resources/pri.der"))))

(deftest tls13-test
  (testing "handshake"
    (is (some? (st/sim-conn
                (fn [client]
                  (let [{:keys [acontext]} (tls13/wrap-stream client (tls13-ctx/->client-context {:ca-certificate-list [@cert] :server-names ["test.local"] :application-protocols ["http/2" "http/1.1"]}))]
                    (assert (= (select-keys @acontext [:stage :cipher-suite :named-group :accept-server-name? :application-protocol])
                               {:stage :connected
                                :cipher-suite tls13-st/cipher-suite-tls-aes-128-gcm-sha256
                                :named-group tls13-st/named-group-x25519
                                :accept-server-name? true
                                :application-protocol "http/1.1"}))))
                (fn [server]
                  (let [{:keys [acontext]} (tls13/wrap-stream server (tls13-ctx/->server-context {:server-certificate-list [{:certificate @cert}] :server-private-key @pri :application-protocols ["http/1.1"]}))]
                    (assert (= (select-keys @acontext [:stage :cipher-suite :named-group :server-names :application-protocol])
                               {:stage :connected
                                :cipher-suite tls13-st/cipher-suite-tls-aes-128-gcm-sha256
                                :named-group tls13-st/named-group-x25519
                                :server-names ["test.local"]
                                :application-protocol "http/1.1"}))))))))
  (testing "handshake secp256r1"
    (is (some? (st/sim-conn
                (fn [client]
                  (let [{:keys [acontext]} (tls13/wrap-stream client (tls13-ctx/->client-context {:ca-certificate-list [@cert] :named-groups [tls13-st/named-group-secp256r1]}))]
                    (assert (= (select-keys @acontext [:stage :named-group])
                               {:stage :connected :named-group tls13-st/named-group-secp256r1}))))
                (fn [server]
                  (let [{:keys [acontext]} (tls13/wrap-stream server (tls13-ctx/->server-context {:server-certificate-list [{:certificate @cert}] :server-private-key @pri}))]
                    (assert (= (select-keys @acontext [:stage :named-group])
                               {:stage :connected :named-group tls13-st/named-group-secp256r1}))))))))
  (testing "client auth"
    (is (some? (st/sim-conn
                (fn [client]
                  (let [{:keys [acontext]} (tls13/wrap-stream client (tls13-ctx/->client-context {:ca-certificate-list [@cert] :client-certificate-list [{:certificate @cert}] :client-private-key @pri}))]
                    (assert (= (select-keys @acontext [:stage :client-auth?])
                               {:stage :connected :client-auth? true}))))
                (fn [server]
                  (let [{:keys [acontext]} (tls13/wrap-stream server (tls13-ctx/->server-context {:client-auth? true :ca-certificate-list [@cert] :server-certificate-list [{:certificate @cert}] :server-private-key @pri}))]
                    (assert (= (select-keys @acontext [:stage])
                               {:stage :connected}))))))))
  (testing "application data"
    (is (some? (st/sim-conn
                (fn [client]
                  (let [{is :input-stream os :output-stream} (tls13/wrap-stream client (tls13-ctx/->client-context {:ca-certificate-list [@cert]}))
                        data (b/rand 32)]
                    (st/write os data)
                    (st/flush os)
                    (assert (zero? (b/compare data (st/read-bytes is 32))))))
                (fn [server]
                  (let [{is :input-stream os :output-stream} (tls13/wrap-stream server (tls13-ctx/->server-context {:server-certificate-list [{:certificate @cert}] :server-private-key @pri}))
                        data (st/read-bytes is 32)]
                    (st/write os data)
                    (st/flush os)))))))
  (testing "key update"
    (is (some? (st/sim-conn
                (fn [client]
                  (let [{:keys [acontext] is :input-stream os :output-stream} (tls13/wrap-stream client (tls13-ctx/->client-context {:ca-certificate-list [@cert]}))
                        data1 (b/rand 32)
                        data2 (b/rand 32)]
                    (st/write os data1)
                    (st/flush os)
                    (swap! acontext tls13-ctx/send-key-update)
                    (st/write os data2)
                    (st/flush os)
                    (assert (zero? (b/compare (b/cat data1 data2) (st/read-bytes is 64))))))
                (fn [server]
                  (let [{:keys [acontext] is :input-stream os :output-stream} (tls13/wrap-stream server (tls13-ctx/->server-context {:server-certificate-list [{:certificate @cert}] :server-private-key @pri}))
                        data (st/read-bytes is 64)]
                    (st/write os data)
                    (st/flush os))))))))
