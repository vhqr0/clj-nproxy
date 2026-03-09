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

(defonce cert (ks/bytes->cert (read-resource "resources/cert.der")))
(defonce pri (ks/bytes->pri "Ed25519" (read-resource "resources/pri.der")))

(def key-store {:certs [cert] :pri pri})
(def trust-store {:certs [cert]})

(deftest tls13-test
  (testing "handshake"
    (is (some? (st/sim-conn
                (fn [server]
                  (tls13/mk-client
                   server {:trust-store trust-store :server-names ["test.local"] :application-protocols ["http/2" "http/1.1"]}
                   (fn [{:keys [acontext] is :input-stream os :output-stream}]
                     (assert (= (select-keys @acontext [:stage :cipher-suite :named-group :accept-server-name? :application-protocol])
                                {:stage :connected
                                 :cipher-suite tls13-st/cipher-suite-tls-aes-128-gcm-sha256
                                 :named-group tls13-st/named-group-x25519
                                 :accept-server-name? true
                                 :application-protocol "http/1.1"}))
                     (st/close os)
                     (st/read-all is))))
                (fn [client]
                  (tls13/mk-server
                   client {:key-store key-store :application-protocols ["http/1.1"]}
                   (fn [{:keys [acontext] is :input-stream os :output-stream}]
                     (assert (= (select-keys @acontext [:stage :cipher-suite :named-group :server-names :application-protocol])
                                {:stage :connected
                                 :cipher-suite tls13-st/cipher-suite-tls-aes-128-gcm-sha256
                                 :named-group tls13-st/named-group-x25519
                                 :server-names ["test.local"]
                                 :application-protocol "http/1.1"}))
                     (st/close os)
                     (st/read-all is))))))))
  (testing "handshake secp256r1"
    (is (some? (st/sim-conn
                (fn [server]
                  (tls13/mk-client
                   server {:trust-store trust-store :named-groups [tls13-st/named-group-secp256r1]}
                   (fn [{:keys [acontext] is :input-stream os :output-stream}]
                     (assert (= (select-keys @acontext [:stage :named-group])
                                {:stage :connected :named-group tls13-st/named-group-secp256r1}))
                     (st/close os)
                     (st/read-all is))))
                (fn [client]
                  (tls13/mk-server
                   client {:key-store key-store}
                   (fn [{:keys [acontext] is :input-stream os :output-stream}]
                     (assert (= (select-keys @acontext [:stage :named-group])
                                {:stage :connected :named-group tls13-st/named-group-secp256r1}))
                     (st/close os)
                     (st/read-all is))))))))
  (testing "client auth"
    (is (some? (st/sim-conn
                (fn [server]
                  (tls13/mk-client
                   server {:trust-store trust-store :key-store key-store}
                   (fn [{:keys [acontext] is :input-stream os :output-stream}]
                     (assert (= (select-keys @acontext [:stage :client-auth?])
                                {:stage :connected :client-auth? true}))
                     (st/close os)
                     (st/read-all is))))
                (fn [client]
                  (tls13/mk-server
                   client {:client-auth? true :trust-store trust-store :key-store key-store}
                   (fn [{:keys [acontext] is :input-stream os :output-stream}]
                     (assert (= (select-keys @acontext [:stage])
                                {:stage :connected}))
                     (st/close os)
                     (st/read-all is))))))))
  (testing "application data"
    (is (some? (st/sim-conn
                (fn [server]
                  (tls13/mk-client
                   server {:trust-store trust-store}
                   (fn [{is :input-stream os :output-stream}]
                     (let [data (b/rand 32)]
                       (st/write os data)
                       (st/flush os)
                       (assert (zero? (b/compare data (st/read-bytes is 32))))
                       (st/close os)
                       (st/read-all is)))))
                (fn [client]
                  (tls13/mk-server
                   client {:key-store key-store}
                   (fn [{is :input-stream os :output-stream}]
                     (let [data (st/read-bytes is 32)]
                       (st/write os data)
                       (st/flush os)
                       (st/close os)
                       (st/read-all is)))))))))
  (testing "key update"
    (is (some? (st/sim-conn
                (fn [server]
                  (tls13/mk-client
                   server {:trust-store trust-store}
                   (fn [{:keys [acontext] is :input-stream os :output-stream}]
                     (let [data1 (b/rand 32)
                           data2 (b/rand 32)]
                       (st/write os data1)
                       (st/flush os)
                       (swap! acontext tls13-ctx/send-key-update)
                       (st/write os data2)
                       (st/flush os)
                       (assert (zero? (b/compare (b/cat data1 data2) (st/read-bytes is 64))))
                       (st/close os)
                       (st/read-all is)))))
                (fn [client]
                  (tls13/mk-server
                   client {:key-store key-store}
                   (fn [{:keys [acontext] is :input-stream os :output-stream}]
                     (let [data (st/read-bytes is 64)]
                       (st/write os data)
                       (st/flush os)
                       (st/close os)
                       (st/read-all is))))))))))
