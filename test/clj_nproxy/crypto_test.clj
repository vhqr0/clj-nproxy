(ns clj-nproxy.crypto-test
  (:require [clojure.test :refer [deftest is]]
            [clj-nproxy.bytes :as b]
            [clj-nproxy.crypto :as crypto]))

(set! clojure.core/*warn-on-reflection* true)

(deftest digest-test
  (is (= "5d41402abc4b2a76b9719d911017c592"
         (-> "hello" b/str->bytes crypto/md5 b/bytes->hex)))
  (is (= "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
         (-> "hello" b/str->bytes crypto/sha256 b/bytes->hex))))

(deftest hmac-test
  (is (= "f1ac9702eb5faf23ca291a4dc46deddeee2a78ccdaf0a412bed7714cfffb1cc4"
         (->> ["hello" "world"] (map b/str->bytes) (apply crypto/hmac-sha256) b/bytes->hex)))
  (is (= "80d036d9974e6f71ceabe493ee897d00235edcc4c72e046ddfc8bf68e86a477d63b9f7d26ad5b990aae6ac17db57ddcf"
         (->> ["hello" "world"] (map b/str->bytes) (apply crypto/hmac-sha384) b/bytes->hex))))

(deftest hkdf-test
  (is (= "67b45533c1158431eb5176fc56fd0fb7"
         (b/bytes->hex (crypto/hkdf-sha256 (b/str->bytes "hello") (b/str->bytes "world") (b/str->bytes "info") 16))))
  (is (= "67b45533c1158431eb5176fc56fd0fb7"
         (b/bytes->hex (crypto/hkdf-expand-sha256 (crypto/hkdf-extract-sha256 (b/str->bytes "hello") (b/str->bytes "world")) (b/str->bytes "info") 16)))))

(deftest ec-test
  (is (crypto/sim-agreement crypto/secp256r1-gen crypto/secp256r1-agreement))
  (is (crypto/sim-agreement crypto/secp384r1-gen crypto/secp384r1-agreement))
  (is (crypto/sim-agreement crypto/secp521r1-gen crypto/secp521r1-agreement))
  (is (crypto/sim-agreement crypto/x25519-gen crypto/x25519-agreement))
  (is (crypto/sim-agreement crypto/x448-gen crypto/x448-agreement))
  (is (crypto/sim-sign-verify crypto/secp256r1-gen crypto/secp256r1-sha256-sign crypto/secp256r1-sha256-verify (b/rand 16)))
  (is (crypto/sim-sign-verify crypto/secp384r1-gen crypto/secp384r1-sha384-sign crypto/secp384r1-sha384-verify (b/rand 16)))
  (is (crypto/sim-sign-verify crypto/secp521r1-gen crypto/secp521r1-sha512-sign crypto/secp521r1-sha512-verify (b/rand 16)))
  (is (crypto/sim-sign-verify crypto/ed25519-gen crypto/ed25519-sign crypto/ed25519-verify (b/rand 16)))
  (is (crypto/sim-sign-verify crypto/ed448-gen crypto/ed448-sign crypto/ed448-verify (b/rand 16))))

(deftest rsa-test
  (is (crypto/sim-sign-verify crypto/rsa-2048-gen crypto/rsa-pkcs1-sha256-sign crypto/rsa-pkcs1-sha256-verify (b/rand 16)))
  (is (crypto/sim-sign-verify crypto/rsa-2048-gen crypto/rsa-pss-rsae-sha256-sign crypto/rsa-pss-rsae-sha256-verify (b/rand 16))))
