(ns clj-nproxy.plugin.tls13.crypto
  "TLS 1.3 crypto definitions."
  (:require [clj-nproxy.bytes :as b]
            [clj-nproxy.struct :as st]
            [clj-nproxy.crypto :as crypto]
            [clj-nproxy.crypto.ecformat :as ecformat]
            [clj-nproxy.plugin.tls13.struct :as tls13-st])
  (:import [java.security PrivateKey PublicKey]
           [java.security.cert Certificate]))

(set! clojure.core/*warn-on-reflection* true)

(defn mask-bytes-inplace
  "Mask bytes one by one inplace."
  [^bytes b1 ^bytes b2]
  (let [b1 (bytes b1)
        b2 (bytes b2)]
    (dotimes [idx (alength b1)]
      (aset b1 idx (unchecked-byte (bit-xor (aget b1 idx) (aget b2 idx)))))))

;;; cipher suites

(def cipher-suite-base-sha256
  {:digest-fn       crypto/sha256
   :digest-size     32
   :hmac-fn         crypto/hmac-sha256
   :hkdf-fn         crypto/hkdf-sha256
   :hkdf-expand-fn  crypto/hkdf-expand-sha256
   :hkdf-extract-fn crypto/hkdf-extract-sha256})

(def cipher-suite-base-sha384
  {:digest-fn       crypto/sha384
   :digest-size     48
   :hmac-fn         crypto/hmac-sha384
   :hkdf-fn         crypto/hkdf-sha384
   :hkdf-expand-fn  crypto/hkdf-expand-sha384
   :hkdf-extract-fn crypto/hkdf-extract-sha384})

(def cipher-suite-tls-aes-128-gcm-sha256
  (merge
   cipher-suite-base-sha256
   {:aead-encrypt-fn crypto/aesgcm-encrypt
    :aead-decrypt-fn crypto/aesgcm-decrypt
    :aead-key-size   16
    :aead-iv-size    12
    :aead-tag-size   16}))

(def cipher-suite-tls-aes-256-gcm-sha384
  (merge
   cipher-suite-base-sha384
   {:aead-encrypt-fn crypto/aesgcm-encrypt
    :aead-decrypt-fn crypto/aesgcm-decrypt
    :aead-key-size   32
    :aead-iv-size    12
    :aead-tag-size   16}))

(def cipher-suite-tls-chacha20-poly1305-sha256
  (merge
   cipher-suite-base-sha256
   {:aead-encrypt-fn crypto/chacha20poly1305-encrypt
    :aead-decrypt-fn crypto/chacha20poly1305-decrypt
    :aead-key-size   32
    :aead-iv-size    12
    :aead-tag-size   16}))

(def cipher-suite-map
  {tls13-st/cipher-suite-tls-aes-128-gcm-sha256       cipher-suite-tls-aes-128-gcm-sha256
   tls13-st/cipher-suite-tls-aes-256-gcm-sha384       cipher-suite-tls-aes-256-gcm-sha384
   tls13-st/cipher-suite-tls-chacha20-poly1305-sha256 cipher-suite-tls-chacha20-poly1305-sha256})

(defn get-cipher-suite
  "Get cipher suite."
  [cipher-suite]
  (or (get cipher-suite-map cipher-suite)
      (throw (ex-info "invalid cipher suite" {:reason ::invalid-cipher-suite :cipher-suite cipher-suite}))))

(defn digest-size
  "Get digest size."
  [cipher-suite]
  (:digest-size (get-cipher-suite cipher-suite)))

(defn digest
  "Message digest."
  ^bytes [cipher-suite & bs]
  (let [{:keys [digest-fn]} (get-cipher-suite cipher-suite)]
    (apply digest-fn bs)))

(defn hmac
  "Hmac."
  ^bytes [cipher-suite ^bytes key & bs]
  (let [{:keys [hmac-fn]} (get-cipher-suite cipher-suite)]
    (apply hmac-fn key bs)))

(defn hkdf-extract
  "Hkdf extract."
  ^bytes [cipher-suite ^bytes ikm ^bytes salt]
  (let [{:keys [hkdf-extract-fn]} (get-cipher-suite cipher-suite)]
    (hkdf-extract-fn ikm salt)))

(defn hkdf-expand
  "Hkdf expand."
  ^bytes [cipher-suite ^bytes prk ^bytes info ^long length]
  (let [{:keys [hkdf-expand-fn]} (get-cipher-suite cipher-suite)]
    (hkdf-expand-fn prk info length)))

(defn hkdf
  "Hkdf."
  ^bytes [cipher-suite ^bytes ikm ^bytes salt ^bytes info ^Long length]
  (let [{:keys [hkdf-fn]} (get-cipher-suite cipher-suite)]
    (hkdf-fn ikm salt info length)))

(def st-hkdf-label
  (st/keys
   :length st/st-ushort-be
   :label (-> (st/->st-var-bytes st/st-ubyte) st/wrap-str)
   :context (st/->st-var-bytes st/st-ubyte)))

(defn hkdf-expand-label
  "Hkdf expand label."
  ^bytes [cipher-suite ^bytes secret ^String label ^bytes context ^Long length]
  (let [info (st/pack st-hkdf-label {:length length :label label :context context})]
    (hkdf-expand cipher-suite secret info length)))

;;; cryptor

(defn ->cryptor
  "Construct cryptor."
  [cipher-suite ^bytes secret]
  (let [{:keys [aead-key-size aead-iv-size]} (get-cipher-suite cipher-suite)
        key (hkdf-expand-label cipher-suite secret tls13-st/label-key (byte-array 0) aead-key-size)
        iv (hkdf-expand-label cipher-suite secret tls13-st/label-iv (byte-array 0) aead-iv-size)]
    {:cipher-suite cipher-suite :secret secret :key key :iv iv :sequence 0}))

(defn aead-tag-size
  "Get aead tag size."
  [cryptor]
  (let [{:keys [cipher-suite]} cryptor]
    (:aead-tag-size (get-cipher-suite cipher-suite))))

(defn sequenced-iv
  "Get seqneuced iv."
  [cryptor]
  (let [{:keys [sequence iv]} cryptor]
    (doto (b/right-align (st/pack-long-be sequence) (b/length iv))
      (mask-bytes-inplace iv))))

(defn encrypt
  "Encrypt data, return new cryptor and encrypted data."
  [cryptor ^bytes data & [^bytes aad]]
  (let [{:keys [cipher-suite key]} cryptor
        {:keys [aead-encrypt-fn]} (get-cipher-suite cipher-suite)]
    [(update cryptor :sequence inc)
     (aead-encrypt-fn key (sequenced-iv cryptor) data aad)]))

(defn decrypt
  "Decrypt data, return new cryptor and decrypted data."
  [cryptor ^bytes data & [^bytes aad]]
  (let [{:keys [key cipher-suite]} cryptor
        {:keys [aead-decrypt-fn]} (get-cipher-suite cipher-suite)]
    [(update cryptor :sequence inc)
     (aead-decrypt-fn key (sequenced-iv cryptor) data aad)]))

(defn update-key
  "Update key."
  [cryptor]
  (let [{:keys [cipher-suite secret]} cryptor
        digest-size (digest-size cipher-suite)
        secret (hkdf-expand-label cipher-suite secret tls13-st/label-key-update (byte-array 0) digest-size)]
    (->cryptor cipher-suite secret)))

;;; named groups

(def named-group-secp256r1
  {:gen-fn        crypto/secp256r1-gen
   :agreement-fn  crypto/secp256r1-agreement
   :pub->bytes-fn ecformat/secp256r1-pub->bytes
   :bytes->pub-fn ecformat/bytes->secp256r1-pub})

(def named-group-secp384r1
  {:gen-fn        crypto/secp384r1-gen
   :agreement-fn  crypto/secp384r1-agreement
   :pub->bytes-fn ecformat/secp384r1-pub->bytes
   :bytes->pub-fn ecformat/bytes->secp384r1-pub})

(def named-group-secp521r1
  {:gen-fn        crypto/secp521r1-gen
   :agreement-fn  crypto/secp521r1-agreement
   :pub->bytes-fn ecformat/secp521r1-pub->bytes
   :bytes->pub-fn ecformat/bytes->secp521r1-pub})

(def named-group-x25519
  {:gen-fn        crypto/x25519-gen
   :agreement-fn  crypto/x25519-agreement
   :pub->bytes-fn ecformat/x25519-pub->bytes
   :bytes->pub-fn ecformat/bytes->x25519-pub})

(def named-group-x448
  {:gen-fn        crypto/x448-gen
   :agreement-fn  crypto/x448-agreement
   :pub->bytes-fn ecformat/x448-pub->bytes
   :bytes->pub-fn ecformat/bytes->x448-pub})

(def named-group-map
  {tls13-st/named-group-secp256r1 named-group-secp256r1
   tls13-st/named-group-secp384r1 named-group-secp384r1
   tls13-st/named-group-secp521r1 named-group-secp521r1
   tls13-st/named-group-x25519    named-group-x25519
   tls13-st/named-group-x448      named-group-x448})

(defn get-named-group
  "Get named group."
  [named-group]
  (or (get named-group-map named-group)
      (throw (ex-info "invalid named group" {:reason ::invalid-named-group :named-group named-group}))))

(defn gen-key-share
  "Generate key share from named group."
  [named-group]
  (let [{:keys [gen-fn]} (get-named-group named-group)
        [pri pub] (gen-fn)]
    {:named-group named-group :pri pri :pub pub}))

(defn key-share->pub-bytes
  "Convert key share to pub."
  ^bytes [key-share]
  (let [{:keys [named-group pub]} key-share
        {:keys [pub->bytes-fn]} (get-named-group named-group)]
    (pub->bytes-fn pub)))

(defn key-agreement
  "Key agreement."
  ^bytes [key-share ^bytes pub-bytes]
  (let [{:keys [named-group pri]} key-share
        {:keys [agreement-fn bytes->pub-fn]} (get-named-group named-group)
        pub (bytes->pub-fn pub-bytes)]
    (agreement-fn pri pub)))

;;; signature schemes

(def signature-scheme-ed25519                {:sign-fn crypto/ed25519-sign             :verify-fn crypto/ed25519-verify})
(def signature-scheme-ed448                  {:sign-fn crypto/ed448-sign               :verify-fn crypto/ed448-verify})
(def signature-scheme-ecdsa-secp256r1-sha256 {:sign-fn crypto/secp256r1-sha256-sign    :verify-fn crypto/secp256r1-sha256-verify})
(def signature-scheme-ecdsa-secp384r1-sha384 {:sign-fn crypto/secp384r1-sha384-sign    :verify-fn crypto/secp384r1-sha384-verify})
(def signature-scheme-ecdsa-secp521r1-sha512 {:sign-fn crypto/secp521r1-sha512-sign    :verify-fn crypto/secp521r1-sha512-verify})
(def signature-scheme-rsa-pss-rsae-sha256    {:sign-fn crypto/rsa-pss-rsae-sha256-sign :verify-fn crypto/rsa-pss-rsae-sha256-verify})
(def signature-scheme-rsa-pss-rsae-sha384    {:sign-fn crypto/rsa-pss-rsae-sha384-sign :verify-fn crypto/rsa-pss-rsae-sha384-verify})
(def signature-scheme-rsa-pss-rsae-sha512    {:sign-fn crypto/rsa-pss-rsae-sha512-sign :verify-fn crypto/rsa-pss-rsae-sha512-verify})
(def signature-scheme-rsa-pkcs1-sha256       {:sign-fn crypto/rsa-pkcs1-sha256-sign    :verify-fn crypto/rsa-pkcs1-sha256-verify})
(def signature-scheme-rsa-pkcs1-sha384       {:sign-fn crypto/rsa-pkcs1-sha384-sign    :verify-fn crypto/rsa-pkcs1-sha384-verify})
(def signature-scheme-rsa-pkcs1-sha512       {:sign-fn crypto/rsa-pkcs1-sha512-sign    :verify-fn crypto/rsa-pkcs1-sha512-verify})

(def signature-scheme-map
  {tls13-st/signature-scheme-ed25519                signature-scheme-ed25519
   tls13-st/signature-scheme-ed448                  signature-scheme-ed448
   tls13-st/signature-scheme-ecdsa-secp256r1-sha256 signature-scheme-ecdsa-secp256r1-sha256
   tls13-st/signature-scheme-ecdsa-secp384r1-sha384 signature-scheme-ecdsa-secp384r1-sha384
   tls13-st/signature-scheme-ecdsa-secp521r1-sha512 signature-scheme-ecdsa-secp521r1-sha512
   tls13-st/signature-scheme-rsa-pss-rsae-sha256    signature-scheme-rsa-pss-rsae-sha256
   tls13-st/signature-scheme-rsa-pss-rsae-sha384    signature-scheme-rsa-pss-rsae-sha384
   tls13-st/signature-scheme-rsa-pss-rsae-sha512    signature-scheme-rsa-pss-rsae-sha512
   tls13-st/signature-scheme-rsa-pkcs1-sha256       signature-scheme-rsa-pkcs1-sha256
   tls13-st/signature-scheme-rsa-pkcs1-sha384       signature-scheme-rsa-pkcs1-sha384
   tls13-st/signature-scheme-rsa-pkcs1-sha512       signature-scheme-rsa-pkcs1-sha512})

(defn get-signature-scheme
  "Get signature scheme."
  [signature-scheme]
  (or (get signature-scheme-map signature-scheme)
      (throw (ex-info "invalid signature scheme" {:reason ::invalid-signature-scheme :signature-scheme signature-scheme}))))

(defn sign
  "Sign signature."
  ^bytes [signature-scheme ^PrivateKey pri ^bytes data]
  (let [{:keys [sign-fn]} (get-signature-scheme signature-scheme)]
    (sign-fn pri data)))

(defn verify
  "Verify signature."
  ^Boolean [signature-scheme ^PublicKey pub ^bytes data ^bytes sig]
  (let [{:keys [verify-fn]} (get-signature-scheme signature-scheme)]
    (verify-fn pub data sig)))

;;; certificate

(def rsa-signature-schemes
  #{tls13-st/signature-scheme-rsa-pss-rsae-sha256
    tls13-st/signature-scheme-rsa-pss-rsae-sha384
    tls13-st/signature-scheme-rsa-pss-rsae-sha512
    tls13-st/signature-scheme-rsa-pkcs1-sha256
    tls13-st/signature-scheme-rsa-pkcs1-sha384
    tls13-st/signature-scheme-rsa-pkcs1-sha512})

(def pub-signature-schemes-map
  {:ed25519   #{tls13-st/signature-scheme-ed25519}
   :ed448     #{tls13-st/signature-scheme-ed448}
   :secp256r1 #{tls13-st/signature-scheme-ecdsa-secp256r1-sha256}
   :secp384r1 #{tls13-st/signature-scheme-ecdsa-secp384r1-sha384}
   :secp521r1 #{tls13-st/signature-scheme-ecdsa-secp521r1-sha512}
   :rsa-2048  rsa-signature-schemes
   :rsa-3072  rsa-signature-schemes
   :rsa-4096  rsa-signature-schemes})

(defn pub->signature-schemes
  "Convert public key to signature schemes."
  [^PublicKey pub]
  (let [type (crypto/pub->type pub)]
    (or (get pub-signature-schemes-map type)
        (throw (ex-info "invalid public key type" {:reason ::invalid-public-key-type :public-key-type type})))))

(defn cert->pub
  "Get certificate public key."
  ^PublicKey [^Certificate cert]
  (.getPublicKey cert))

(defn verify-cert
  "Verify crtificate."
  [^Certificate cert ^PublicKey pub]
  (.verify cert pub))

(defn verify-cert-chain
  "Verify certificate chain."
  [certs]
  (->> certs
       (partition 2 1)
       (run!
        (fn [[ee ca]]
          (verify-cert ee (cert->pub ca))))))

;;; key schedule

(defn derive-secret
  "Derive secret."
  ^bytes [cipher-suite ^bytes secret ^String label msgs]
  (let [digest-size (digest-size cipher-suite)
        context (apply digest cipher-suite msgs)]
    (hkdf-expand-label cipher-suite secret label context digest-size)))

(defn early-secret
  "Derive early secret."
  (^bytes [cipher-suite]
   (let [digest-size (digest-size cipher-suite)]
     (early-secret cipher-suite (byte-array digest-size))))
  (^bytes [cipher-suite ^bytes psk]
   (let [digest-size (digest-size cipher-suite)]
     (hkdf-extract cipher-suite psk (byte-array digest-size)))))

(defn handshake-secret
  "Derive handshake secret."
  ^bytes [cipher-suite ^bytes early-secret ^bytes shared-secret]
  (let [derived (derive-secret cipher-suite early-secret tls13-st/label-derived nil)]
    (hkdf-extract cipher-suite shared-secret derived)))

;; client hello ... server hello
(defn client-handshake-secret
  "Expand client handshake secret."
  ^bytes [cipher-suite ^bytes handshake-secret msgs]
  (derive-secret cipher-suite handshake-secret tls13-st/label-client-handshake msgs))

;; client hello ... server hello
(defn server-handshake-secret
  "Expand server handshake secret."
  ^bytes [cipher-suite ^bytes handshake-secret msgs]
  (derive-secret cipher-suite handshake-secret tls13-st/label-server-handshake msgs))

(defn handshake-verify-key
  "Expand handshake verify key."
  ^bytes [cipher-suite ^bytes handshake-secret]
  (let [digest-size (digest-size cipher-suite)]
    (hkdf-expand-label cipher-suite handshake-secret tls13-st/label-finished (byte-array 0) digest-size)))

;; client: client hello ... server finished / client certificate verify
;; server: client hello ... server certificate verify
(defn handshake-verify
  "Verify handshake."
  ^bytes [cipher-suite ^bytes handshake-secret msgs]
  (let [key (handshake-verify-key cipher-suite handshake-secret)]
    (hmac cipher-suite key (apply digest cipher-suite msgs))))

(defn master-secret
  "Derive master secret."
  ^bytes [cipher-suite ^bytes handshake-secret]
  (let [digest-size (digest-size cipher-suite)
        derived (derive-secret cipher-suite handshake-secret tls13-st/label-derived nil)]
    (hkdf-extract cipher-suite (byte-array digest-size) derived)))

;; client hello ... server finished
(defn client-application-secret
  "Expand client application secret."
  ^bytes [cipher-suite ^bytes master-secret msgs]
  (derive-secret cipher-suite master-secret tls13-st/label-client-application msgs))

;; client hello ... server finished
(defn server-application-secret
  "Expand server application secret."
  ^bytes [cipher-suite ^bytes master-secret msgs]
  (derive-secret cipher-suite master-secret tls13-st/label-server-application msgs))
