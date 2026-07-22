(ns clj-nproxy.crypto.ecformat-test
  (:require [clojure.test :refer [deftest is]]
            [clj-nproxy.bytes :as b]
            [clj-nproxy.crypto :as crypto]
            [clj-nproxy.crypto.ecformat :as ecf]))

(defn sim-agreement
  "Simulate key agreement."
  [gen-fn agreement-fn pub->bytes-fn bytes->pub-fn]
  (let [[pri1 pub1] (gen-fn)
        [pri2 pub2] (gen-fn)]
    (zero? (b/compare
            (agreement-fn pri1 (-> pub2 pub->bytes-fn bytes->pub-fn))
            (agreement-fn pri2 (-> pub1 pub->bytes-fn bytes->pub-fn))))))

(deftest agreement-test
  (is (sim-agreement crypto/secp256r1-gen crypto/secp256r1-agreement ecf/secp256r1-pub->bytes ecf/bytes->secp256r1-pub))
  (is (sim-agreement crypto/secp384r1-gen crypto/secp384r1-agreement ecf/secp384r1-pub->bytes ecf/bytes->secp384r1-pub))
  (is (sim-agreement crypto/secp521r1-gen crypto/secp521r1-agreement ecf/secp521r1-pub->bytes ecf/bytes->secp521r1-pub))
  (is (sim-agreement crypto/x25519-gen crypto/x25519-agreement ecf/x25519-pub->bytes ecf/bytes->x25519-pub))
  (is (sim-agreement crypto/x448-gen crypto/x448-agreement ecf/x448-pub->bytes ecf/bytes->x448-pub)))


