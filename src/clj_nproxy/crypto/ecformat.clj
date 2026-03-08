(ns clj-nproxy.crypto.ecformat
  "Raw ec key format."
  (:require [clj-nproxy.bytes :as b]
            [clj-nproxy.crypto :as crypto])
  (:import [java.security KeyFactory AlgorithmParameters]
           [java.security.spec ECPoint ECParameterSpec ECGenParameterSpec ECPublicKeySpec XECPublicKeySpec NamedParameterSpec]
           [java.security.interfaces ECPublicKey XECPublicKey]))

(set! clojure.core/*warn-on-reflection* true)

;;; ec

(defn ec-pub->bytes
  "Convert ec public key to bytes."
  ^bytes [^long len ^ECPublicKey pub]
  (let [^ECPoint w (.getW pub)
        x (-> (.toByteArray (.getAffineX w)) (b/right-align len))
        y (-> (.toByteArray (.getAffineY w)) (b/right-align len))]
    (b/cat (byte-array [4]) x y)))

(defn ec-params
  "Make ec params."
  ^ECParameterSpec [^String name]
  (let [params (doto (AlgorithmParameters/getInstance "EC")
                 (.init (ECGenParameterSpec. name)))]
    (.getParameterSpec params ECParameterSpec)))

(defn bytes->ec-pub
  "Convert bytes to ec public key."
  ^ECPublicKey [^String name ^long len ^bytes b]
  (if (and (= (inc (* 2 len)) (alength b)) (= 4 (aget b 0)))
    (let [x (b/copy-of-range b 1 (inc len))
          y (b/copy-of-range b (inc len) (inc (* 2 len)))
          w (ECPoint. (BigInteger. 1 (bytes x)) (BigInteger. 1 (bytes y)))
          spec (ECPublicKeySpec. w (ec-params name))]
      (-> (KeyFactory/getInstance "EC")
          (.generatePublic spec)))
    (throw (ex-info "invalid length" {:reason ::invalid-length}))))

(def secp256r1-pub->bytes (partial ec-pub->bytes 32))
(def secp384r1-pub->bytes (partial ec-pub->bytes 48))
(def secp521r1-pub->bytes (partial ec-pub->bytes 66))
(def bytes->secp256r1-pub (partial bytes->ec-pub "secp256r1" 32))
(def bytes->secp384r1-pub (partial bytes->ec-pub "secp384r1" 48))
(def bytes->secp521r1-pub (partial bytes->ec-pub "secp521r1" 66))

;;; xec

(defn xec-pub->bytes
  "Convert xec public key to bytes."
  ^bytes [len ^XECPublicKey pub]
  (-> (.toByteArray (.getU pub))
      (b/right-align len)
      b/reverse))

(defn bytes->xec-pub
  "Convert bytes to xec public key."
  ^XECPublicKey [name ^bytes b]
  (let [spec (XECPublicKeySpec.
              (NamedParameterSpec. name)
              (BigInteger. 1 (b/reverse b)))]
    (-> (KeyFactory/getInstance name)
        (.generatePublic spec))))

(def x25519-pub->bytes (partial xec-pub->bytes 32))
(def x448-pub->bytes (partial xec-pub->bytes 56))
(def bytes->x25519-pub (partial bytes->xec-pub "X25519"))
(def bytes->x448-pub (partial bytes->xec-pub "X448"))

;;; test

(defn sim-agreement
  "Simulate key agreement."
  [gen-fn agreement-fn pub->bytes-fn bytes->pub-fn]
  (let [[pri1 pub1] (gen-fn)
        [pri2 pub2] (gen-fn)]
    (zero? (b/compare
            (agreement-fn pri1 (-> pub2 pub->bytes-fn bytes->pub-fn))
            (agreement-fn pri2 (-> pub1 pub->bytes-fn bytes->pub-fn))))))

^:rct/test
(comment
  (sim-agreement crypto/secp256r1-gen crypto/secp256r1-agreement secp256r1-pub->bytes bytes->secp256r1-pub) ; => true
  (sim-agreement crypto/secp384r1-gen crypto/secp384r1-agreement secp384r1-pub->bytes bytes->secp384r1-pub) ; => true
  (sim-agreement crypto/secp521r1-gen crypto/secp521r1-agreement secp521r1-pub->bytes bytes->secp521r1-pub) ; => true
  (sim-agreement crypto/x25519-gen crypto/x25519-agreement x25519-pub->bytes bytes->x25519-pub) ; => true
  (sim-agreement crypto/x448-gen crypto/x448-agreement x448-pub->bytes bytes->x448-pub) ; => true
  )
