(ns clj-nproxy.crypto
  "Java crypto wrapper."
  (:require [clj-nproxy.bytes :as b])
  (:import [java.security MessageDigest Signature PublicKey PrivateKey KeyPair KeyPairGenerator]
           [java.security.spec AlgorithmParameterSpec ECGenParameterSpec]
           [javax.crypto Mac KDF Cipher KeyAgreement]
           [javax.crypto.spec SecretKeySpec HKDFParameterSpec IvParameterSpec GCMParameterSpec]))

(set! clojure.core/*warn-on-reflection* true)

;;; digest

(defn digest
  "Digest."
  ^bytes [^String algo & bs]
  (let [md (MessageDigest/getInstance algo)]
    (run! #(.update md (bytes %)) bs)
    (.digest md)))

(def md5 (partial digest "MD5"))
(def sha1 (partial digest "SHA-1"))
(def sha224 (partial digest "SHA-224"))
(def sha256 (partial digest "SHA-256"))
(def sha384 (partial digest "SHA-384"))
(def sha512 (partial digest "SHA-512"))

^:rct/test
(comment
  (b/bytes->hex (md5 (.getBytes "hello"))) ; => "5d41402abc4b2a76b9719d911017c592"
  (b/bytes->hex (sha256 (.getBytes "hello"))) ; => "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
  )

;;; hmac

(defn hmac
  "Hmac."
  ^bytes [^String algo ^bytes key & bs]
  (let [mac (doto (Mac/getInstance algo)
              (.init (SecretKeySpec. key algo)))]
    (run! #(.update mac (bytes %)) bs)
    (.doFinal mac)))

(def hmac-sha256 (partial hmac "HMACSHA256"))
(def hmac-sha384 (partial hmac "HMACSHA384"))

^:rct/test
(comment
  (b/bytes->hex (hmac-sha256 (.getBytes "hello") (.getBytes "world"))) ; => "f1ac9702eb5faf23ca291a4dc46deddeee2a78ccdaf0a412bed7714cfffb1cc4"
  (b/bytes->hex (hmac-sha384 (.getBytes "hello") (.getBytes "world"))) ; => "80d036d9974e6f71ceabe493ee897d00235edcc4c72e046ddfc8bf68e86a477d63b9f7d26ad5b990aae6ac17db57ddcf"
  )

;;; hkdf

(defn hkdf-extract
  "Hkdf extract."
  ^bytes [^String algo ^bytes ikm ^bytes salt]
  (let [kdf (KDF/getInstance algo)
        params (-> (HKDFParameterSpec/ofExtract)
                   (.addIKM ikm)
                   (.addSalt salt)
                   (.extractOnly))]
    (.deriveData kdf params)))

(defn hkdf-expand
  "Hkdf expand."
  ^bytes [^String algo ^bytes prk ^bytes info ^long length]
  (let [kdf (KDF/getInstance algo)
        params (HKDFParameterSpec/expandOnly (SecretKeySpec. prk algo) (bytes info) (int length))]
    (.deriveData kdf params)))

(defn hkdf
  "Hkdf."
  ^bytes [^String algo ^bytes ikm ^bytes salt ^bytes info ^Long length]
  (let [kdf (KDF/getInstance algo)
        params (-> (HKDFParameterSpec/ofExtract)
                   (.addIKM ikm)
                   (.addSalt salt)
                   (.thenExpand info length))]
    (.deriveData kdf params)))

(def hkdf-extract-sha256 (partial hkdf-extract "HKDF-SHA256"))
(def hkdf-extract-sha384 (partial hkdf-extract "HKDF-SHA384"))
(def hkdf-expand-sha256 (partial hkdf-expand "HKDF-SHA256"))
(def hkdf-expand-sha384 (partial hkdf-expand "HKDF-SHA384"))
(def hkdf-sha256 (partial hkdf "HKDF-SHA256"))
(def hkdf-sha384 (partial hkdf "HKDF-SHA384"))

^:rct/test
(comment
  (b/bytes->hex (hkdf-sha256 (.getBytes "hello") (.getBytes "world") (.getBytes "info") 16)) ; => "67b45533c1158431eb5176fc56fd0fb7"
  (b/bytes->hex (hkdf-expand-sha256 (hkdf-extract-sha256 (.getBytes "hello") (.getBytes "world")) (.getBytes "info") 16)) ; => "67b45533c1158431eb5176fc56fd0fb7"
  )

;;; crypt

(defn crypt
  "Encrypt/Decrypt."
  ^bytes [^Long mode ^String algo ^SecretKeySpec key ^AlgorithmParameterSpec params ^bytes data ^bytes aad]
  (let [cipher (doto (Cipher/getInstance algo)
                 (.init (int mode) key params))]
    (when (some? aad)
      (.updateAAD cipher aad))
    (.doFinal cipher data)))

(def encrypt (partial crypt Cipher/ENCRYPT_MODE))
(def decrypt (partial crypt Cipher/DECRYPT_MODE))

(defn aes-key
  "Make aes key."
  ^SecretKeySpec [^bytes key]
  (SecretKeySpec. key "AES"))

(defn chacha20-key
  "Make chacha20 key."
  ^SecretKeySpec [^bytes key]
  (SecretKeySpec. key "ChaCha20"))

(defn iv-params
  "Make iv params."
  ^AlgorithmParameterSpec [^bytes iv]
  (IvParameterSpec. iv))

(defn gcm-params
  "Make gcm params."
  (^AlgorithmParameterSpec [^bytes iv]
   (gcm-params 128 iv))
  (^AlgorithmParameterSpec [^long tlen ^bytes iv]
   (GCMParameterSpec. tlen iv)))

(defn aesgcm-encrypt [key iv data & [aad]] (encrypt "AES/GCM/NoPadding" (aes-key key) (gcm-params iv) data aad))
(defn aesgcm-decrypt [key iv data & [aad]] (decrypt "AES/GCM/NoPadding" (aes-key key) (gcm-params iv) data aad))
(defn chacha20poly1305-encrypt [key iv data & [aad]] (encrypt "ChaCha20-Poly1305" (chacha20-key key) (iv-params iv) data aad))
(defn chacha20poly1305-decrypt [key iv data & [aad]] (decrypt "ChaCha20-Poly1305" (chacha20-key key) (iv-params iv) data aad))

;;; asymmetric

(defn kp-gen
  "Keypair generation."
  ([^String algo]
   (kp-gen algo nil))
  ([^String algo ^AlgorithmParameterSpec params]
   (let [kpg (KeyPairGenerator/getInstance algo)]
     (when (some? params)
       (.initialize kpg params))
     (let [kp (.generateKeyPair kpg)]
       [(.getPrivate kp) (.getPublic kp)]))))

(defn sign
  "Sign signature."
  ^bytes [^String algo ^PrivateKey pri ^bytes data]
  (let [signer (doto (Signature/getInstance algo)
                 (.initSign pri)
                 (.update data))]
    (.sign signer)))

(defn verify
  "Verify signature."
  ^Boolean [^String algo ^PublicKey pub ^bytes data ^bytes sig]
  (let [verifier (doto (Signature/getInstance algo)
                   (.initVerify pub)
                   (.update data))]
    (.verify verifier sig)))

(defn agreement
  "Key agreement."
  ^bytes [^String algo ^PrivateKey pri ^PublicKey pub]
  (let [ka (doto (KeyAgreement/getInstance algo)
             (.init pri)
             (.doPhase pub true))]
    (.generateSecret ka)))

(defn sim-sign-verify
  "Simulate sign and verify."
  [gen-fn sign-fn verify-fn data]
  (let [[pri pub] (gen-fn)
        sig (sign-fn pri data)]
    (verify-fn pub data sig)))

(defn sim-agreement
  "Simulate key agreement."
  [gen-fn agreement-fn]
  (let [[pri1 pub1] (gen-fn)
        [pri2 pub2] (gen-fn)]
    (zero? (b/compare
            (agreement-fn pri1 pub2)
            (agreement-fn pri2 pub1)))))

;;;; ecc

(defn ec-gen-params
  "Make ec generation params."
  ^AlgorithmParameterSpec [^String name]
  (ECGenParameterSpec. name))

(defn secp256r1-gen [] (kp-gen "EC" (ec-gen-params "secp256r1")))
(defn secp384r1-gen [] (kp-gen "EC" (ec-gen-params "secp384r1")))
(defn secp521r1-gen [] (kp-gen "EC" (ec-gen-params "secp521r1")))
(def ec-agreement (partial agreement "ECDH"))
(def secp256r1-agreement ec-agreement)
(def secp384r1-agreement ec-agreement)
(def secp521r1-agreement ec-agreement)
(def secp256r1-sha256-sign (partial sign "SHA256withECDSA"))
(def secp384r1-sha384-sign (partial sign "SHA384withECDSA"))
(def secp521r1-sha512-sign (partial sign "SHA512withECDSA"))
(def secp256r1-sha256-verify (partial verify "SHA256withECDSA"))
(def secp384r1-sha384-verify (partial verify "SHA384withECDSA"))
(def secp521r1-sha512-verify (partial verify "SHA512withECDSA"))

(def x25519-gen (partial kp-gen "X25519"))
(def x448-gen (partial kp-gen "X448"))
(def x25519-agreement (partial agreement "X25519"))
(def x448-agreement (partial agreement "X448"))

(def ed25519-gen (partial kp-gen "Ed25519"))
(def ed448-gen (partial kp-gen "Ed448"))
(def ed25519-sign (partial sign "Ed25519"))
(def ed448-sign (partial sign "Ed448"))
(def ed25519-verify (partial verify "Ed25519"))
(def ed448-verify (partial verify "Ed448"))

^:rct/test
(comment
  (sim-agreement secp256r1-gen secp256r1-agreement) ; => true
  (sim-agreement secp384r1-gen secp384r1-agreement) ; => true
  (sim-agreement secp521r1-gen secp521r1-agreement) ; => true
  (sim-agreement x25519-gen x25519-agreement) ; => true
  (sim-agreement x448-gen x448-agreement) ; => true
  (sim-sign-verify secp256r1-gen secp256r1-sha256-sign secp256r1-sha256-verify (b/rand 16)) ; => true
  (sim-sign-verify secp384r1-gen secp384r1-sha384-sign secp384r1-sha384-verify (b/rand 16)) ; => true
  (sim-sign-verify secp521r1-gen secp521r1-sha512-sign secp521r1-sha512-verify (b/rand 16)) ; => true
  (sim-sign-verify ed25519-gen ed25519-sign ed25519-verify (b/rand 16)) ; => true
  (sim-sign-verify ed448-gen ed448-sign ed448-verify (b/rand 16)) ; => true
  )
