(ns clj-nproxy.plugin.tls13
  "TLS 1.3 impl."
  (:require [clojure.set :as set]
            [clj-nproxy.bytes :as b]
            [clj-nproxy.struct :as st]
            [clj-nproxy.crypto :as crypto]
            [clj-nproxy.crypto.ecformat :as ecf]
            [clj-nproxy.crypto.keystore :as ks])
  (:import [java.io InputStream OutputStream BufferedInputStream BufferedOutputStream]
           [java.security PrivateKey PublicKey]))

;; RFC 8446 TLS 1.3

(set! clojure.core/*warn-on-reflection* true)

(def vec-conj (fnil conj []))
(def vec-drop (comp vec drop))

(defn mask-bytes-inplace
  "Mask bytes one by one inplace."
  [^bytes b1 ^bytes b2]
  (let [b1 (bytes b1)
        b2 (bytes b2)]
    (dotimes [idx (alength b1)]
      (aset b1 idx (unchecked-byte (bit-xor (aget b1 idx) (aget b2 idx)))))))

;;; struct

(def st-uint24
  (-> (st/->st-bytes 3)
      (st/wrap
       #(st/unpack st/st-uint-be (b/right-align % 4))
       #(b/copy-of-range (st/pack st/st-uint-be %) 1 4))))

^:rct/test
(comment
  (seq (st/pack st-uint24 1)) ; => [0 0 1]
  (st/unpack st-uint24 (byte-array [0 0 1])) ; => 1
  )

;;;; const

;;;;; label

(def label-derived               "tls13 derived")
(def label-external-binder       "tls13 ext binder")
(def label-resumption-binder     "tls13 res binder")
(def label-resumption-master     "tls13 res master")
(def label-resumption            "tls13 resumption")
(def label-exporter-master       "tls13 exp master")
(def label-early-exporter-master "tls13 e exp master")
(def label-client-early          "tls13 c e traffic")
(def label-client-handshake      "tls13 c hs traffic")
(def label-server-handshake      "tls13 s hs traffic")
(def label-client-application    "tls13 c ap traffic")
(def label-server-application    "tls13 s ap traffic")
(def label-key-update            "tls13 traffic upd")
(def label-key                   "tls13 key")
(def label-iv                    "tls13 iv")
(def label-finished              "tls13 finished")

;;;;; version

(def version-ssl30 0x0300)
(def version-tls10 0x0301)
(def version-tls11 0x0302)
(def version-tls12 0x0303)
(def version-tls13 0x0304)

(def st-protocol-version st/st-ushort-be)
(def st-protocol-version-list
  (-> (st/->st-var-bytes st/st-ubyte)
      (st/wrap-many-struct st-protocol-version)))

;;;;; compression

(def compression-method-null 0)

(def st-compression-method st/st-ubyte)
(def st-compression-method-list
  (-> (st/->st-var-bytes st/st-ubyte)
      (st/wrap-many-struct st-compression-method)))

;;;;; signature scheme

(def signature-scheme-rsa-pkcs1-sha256       0x0401)
(def signature-scheme-rsa-pkcs1-sha384       0x0501)
(def signature-scheme-rsa-pkcs1-sha512       0x0601)
(def signature-scheme-ecdsa-secp256r1-sha256 0x0403)
(def signature-scheme-ecdsa-secp384r1-sha384 0x0503)
(def signature-scheme-ecdsa-secp521r1-sha512 0x0603)
(def signature-scheme-rsa-pss-rsae-sha256    0x0804)
(def signature-scheme-rsa-pss-rsae-sha384    0x0805)
(def signature-scheme-rsa-pss-rsae-sha512    0x0806)
(def signature-scheme-ed25519                0x0807)
(def signature-scheme-ed448                  0x0808)
(def signature-scheme-rsa-pss-pss-sha256     0x0809)
(def signature-scheme-rsa-pss-pss-sha384     0x080a)
(def signature-scheme-rsa-pss-pss-sha512     0x080b)
(def signature-scheme-rsa-pkcs1-sha1         0x0201)
(def signature-scheme-ecdsa-sha1             0x0203)

(def st-signature-scheme st/st-ushort-be)
(def st-signature-scheme-list
  (-> (st/->st-var-bytes st/st-ushort-be)
      (st/wrap-many-struct st-signature-scheme)))

;;;;; cipher suite

(def cipher-suite-tls-aes-128-gcm-sha256       0x1301)
(def cipher-suite-tls-aes-256-gcm-sha384       0x1302)
(def cipher-suite-tls-chacha20-poly1305-sha256 0x1303)
(def cipher-suite-tls-aes-128-ccm-sha256       0x1304)
(def cipher-suite-tls-aes-128-ccm-8-sha256     0x1305)

(def st-cipher-suite st/st-ushort-be)
(def st-cipher-suite-list
  (-> (st/->st-var-bytes st/st-ushort-be)
      (st/wrap-many-struct st-cipher-suite)))

;;;;; named group

(def named-group-secp256r1 0x0017)
(def named-group-secp384r1 0x0018)
(def named-group-secp521r1 0x0019)
(def named-group-x25519    0x001d)
(def named-group-x448      0x001e)
(def named-group-ffdhe2048 0x0100)
(def named-group-ffdhe3072 0x0101)
(def named-group-ffdhe4096 0x0102)
(def named-group-ffdhe6144 0x0103)
(def named-group-ffdhe8192 0x0104)

(def st-named-group st/st-ushort-be)
(def st-named-group-list
  (-> (st/->st-var-bytes st/st-ushort-be)
      (st/wrap-many-struct st-named-group)))

;;;; record

(def content-type-change-cipher-spec 20)
(def content-type-alert              21)
(def content-type-handshake          22)
(def content-type-application-data   23)

(def st-content-type st/st-ubyte)

(def st-record-header
  (st/keys
   :type st-content-type
   :version st-protocol-version
   :length st/st-ushort-be))

(def st-record
  (st/keys
   :type st-content-type
   :version st-protocol-version
   :content (st/->st-var-bytes st/st-ushort-be)))

(defn unpack-inner-plaintext
  "Unpack inner plaintext."
  [^bytes b]
  (let [b (bytes b)
        l (alength b)
        i (loop [i (dec l)]
            (if (zero? i)
              (throw (ex-info "invalid plaintext" {:reason ::invalid-plaintext}))
              (if-not (zero? (aget b i))
                i
                (recur (dec i)))))
        type (aget b i)
        content (b/copy-of b i)]
    [type content (dec (- l i))]))

(defn pack-inner-plaintext
  "Pack inner plaintext."
  ([type content]
   (b/cat content (byte-array [type])))
  ([type content plen]
   (b/cat content (byte-array [type]) (byte-array plen))))

^:rct/test
(comment
  (-> (unpack-inner-plaintext (byte-array [1 2 3 4 0 0])) (update 1 seq)) ; => [4 [1 2 3] 2]
  (seq (pack-inner-plaintext 1 (byte-array [2 3 4]))) ; => [2 3 4 1]
  (seq (pack-inner-plaintext 1 (byte-array [2 3 4]) 2)) ; => [2 3 4 1 0 0]
  )

;;;;; change cipher spec

(def change-ciper-spec 1)

(def st-change-cipher-spec st/st-ubyte)

;;;;; alert

(def alert-level-warning 1)
(def alert-level-fatal   2)

(def st-alert-level st/st-ubyte)

(def alert-description-close-notify                    0)
(def alert-description-unexpected-message              10)
(def alert-description-bad-record-mac                  20)
(def alert-description-record-overflow                 22)
(def alert-description-handshake-failure               40)
(def alert-description-bad-certificate                 42)
(def alert-description-unsupported-certificate         43)
(def alert-description-certificate-revoked             44)
(def alert-description-certificate-expired             45)
(def alert-description-certificate-unknown             46)
(def alert-description-illegal-parameter               47)
(def alert-description-unknown-ca                      48)
(def alert-description-access-denied                   49)
(def alert-description-decode-error                    50)
(def alert-description-decrypt-error                   51)
(def alert-description-protocol-version                70)
(def alert-description-insufficient-security           71)
(def alert-description-internal-error                  80)
(def alert-description-inappropriate-fallback          86)
(def alert-description-user-canceled                   90)
(def alert-description-missing-extension               109)
(def alert-description-unsupported-extension           110)
(def alert-description-unrecognized-name               112)
(def alert-description-bad-certificate-status-response 113)
(def alert-description-unknown-psk-identity            115)
(def alert-description-certificate-required            116)
(def alert-description-no-application-protocol         120)

(def st-alert-description st/st-ubyte)

(def st-alert
  (st/keys :level st-alert-level :description st-alert-description))

;;;; handshake

;;;;; extension

(def extension-type-server-name                            0)
(def extension-type-max-fragment-length                    1)
(def extension-type-status-request                         5)
(def extension-type-supported-groups                       10)
(def extension-type-signature-algorithms                   13)
(def extension-type-use-srtp                               14)
(def extension-type-heartbeat                              15)
(def extension-type-application-layer-protocol-negotiation 16)
(def extension-type-signed-certificate-timestamp           18)
(def extension-type-client-certificate-type                19)
(def extension-type-server-certificate-type                20)
(def extension-type-padding                                21)
(def extension-type-pre-shared-key                         41)
(def extension-type-early-data                             42)
(def extension-type-supported-versions                     43)
(def extension-type-cookie                                 44)
(def extension-type-psk-key-exchange-modes                 45)
(def extension-type-certificate-authorities                47)
(def extension-type-oid-filters                            48)
(def extension-type-post-handshake-auth                    49)
(def extension-type-signature-algorithms-cert              50)
(def extension-type-key-share                              51)

(def st-extension-type st/st-ushort-be)

(def st-extension
  (st/keys
   :extension-type st-extension-type
   :extension-data (st/->st-var-bytes st/st-ushort-be)))

(def st-extension-list
  (-> (st/->st-var-bytes st/st-ushort-be)
      (st/wrap-many-struct st-extension)))

;;;;; handshake

(def handshake-type-client-hello         1)
(def handshake-type-server-hello         2)
(def handshake-type-new-session-ticket   4)
(def handshake-type-end-of-early-data    5)
(def handshake-type-encrypted-extensions 8)
(def handshake-type-certificate          11)
(def handshake-type-certificate-request  13)
(def handshake-type-certificate-verify   15)
(def handshake-type-finished             20)
(def handshake-type-key-update           24)
(def handshake-type-message-hash         254)

(def st-handshake-type st/st-ubyte)

(def st-handshake
  (st/keys
   :msg-type st-handshake-type
   :msg-data (st/->st-var-bytes st-uint24)))

(def st-handshake-client-hello
  (st/keys
   :legacy-version st-protocol-version
   :random (st/->st-bytes 32)
   :legacy-session-id (st/->st-var-bytes st/st-ubyte)
   :cipher-suites st-cipher-suite-list
   :legacy-compression-methods st-compression-method-list
   :extensions st-extension-list))

(def st-handshake-server-hello
  (st/keys
   :legacy-version st-protocol-version
   :random (st/->st-bytes 32)
   :legacy-session-id-echo (st/->st-var-bytes st/st-ubyte)
   :cipher-suite st-cipher-suite
   :legacy-compression-method st-compression-method
   :extensions st-extension-list))

(def hello-retry-request-random
  "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")

(def tls12-random "444F574E47524401")
(def tls11-random "444F574E47524400")

(def st-handshake-encrypted-extensions st-extension-list)

(def server-signature-context-string "TLS 1.3, server CertificateVerify")
(def client-signature-context-string "TLS 1.3, client CertificateVerify")

(defn pack-signature-data
  "Pack signature data."
  ^bytes [^String context ^bytes data]
  (b/cat
   (doto (byte-array 64) (b/fill 0x20))
   (b/str->bytes context)
   (byte-array 1)
   data))

(def certificate-type-x509           0)
(def certificate-type-raw-public-key 2)

(def st-certificate-type st/st-ubyte)

(def st-certificate-entry
  (st/keys
   :cert-data (st/->st-var-bytes st-uint24)
   :extensions st-extension-list))

(def st-certificate-entry-list
  (-> (st/->st-var-bytes st-uint24)
      (st/wrap-many-struct st-certificate-entry)))

(def st-handshake-certificate
  (st/keys
   :certificate-request-context (st/->st-var-bytes st/st-ubyte)
   :certificate-list st-certificate-entry-list))

(def st-handshake-certificate-verify
  (st/keys
   :algorithm st-signature-scheme
   :signature (st/->st-var-bytes st/st-ushort-be)))

(def st-handshake-certificate-request
  (st/keys
   :certificate-request-context (st/->st-var-bytes st/st-ubyte)
   :extensions st-extension-list))

(def st-handshake-end-of-early-data st/st-null)

(def st-handshake-new-session-ticket
  (st/keys
   :ticket-lifetime st/st-uint-be
   :ticket-age-add st/st-uint-be
   :ticket-nonce (st/->st-var-bytes st/st-ubyte)
   :ticket (st/->st-var-bytes st/st-ushort-be)
   :extensions st-extension-list))

(def key-update-not-requested 0)
(def key-update-requested     1)

(def st-handshake-key-update st/st-ubyte)

;;;;; supported versions

(def st-extension-supported-versions-client-hello st-protocol-version-list)
(def st-extension-supported-versions-server-hello st-protocol-version)

;;;;; cookie

(def st-extension-cookie (st/->st-var-bytes st/st-ushort-be))

;;;;; signature algorithms

(def st-extension-signature-algorithms st-signature-scheme-list)

;;;;; certificate authorities

(def st-distinguished-name (st/->st-var-bytes st/st-ushort-be))
(def st-distinguished-name-list
  (-> (st/->st-var-bytes st/st-ushort-be)
      (st/wrap-many-struct st-distinguished-name)))

(def st-extension-certificate-authorities st-distinguished-name-list)

;;;;; oid filters

(def st-oid-filter
  (st/keys
   :certificate-extension-oid (st/->st-var-bytes st/st-ubyte)
   :certificate-extension-values (st/->st-var-bytes st/st-ushort-be)))

(def st-oid-filter-list
  (-> (st/->st-var-bytes st/st-ushort-be)
      (st/wrap-many-struct st-oid-filter)))

(def st-extension-oid-filters st-oid-filter-list)

;;;;; post handshake auth

(def st-extension-post-handshake-auth st/st-null)

;;;;; supported groups

(def st-extension-supported-groups st-named-group-list)

;;;;; key share

(def st-key-share-entry
  (st/keys
   :group st-named-group
   :key-exchange (st/->st-var-bytes st/st-ushort-be)))

(def st-key-share-entry-list
  (-> (st/->st-var-bytes st/st-ushort-be)
      (st/wrap-many-struct st-key-share-entry)))

(def st-extension-key-share-client-hello st-key-share-entry-list)
(def st-extension-key-share-hello-retry-request st-named-group)
(def st-extension-key-share-server-hello st-key-share-entry)

;;;;; psk key exchange modes

(def psk-key-exchange-mode-ke     0)
(def psk-key-exchange-mode-dhe-ke 1)

(def st-psk-key-exchange-mode st/st-ubyte)
(def st-psk-key-exchange-mode-list
  (-> (st/->st-var-bytes st/st-ubyte)
      (st/wrap-many-struct st-psk-key-exchange-mode)))

(def st-extension-psk-key-exchange-modes st-psk-key-exchange-mode-list)

;;;;; early data

(def st-extension-early-data-new-session-ticket st/st-uint-be)
(def st-extension-early-data-client-hello st/st-null)
(def st-extension-early-data-encrypted-extensions st/st-null)

;;;;; pre shared key

(def st-psk-identity
  (st/keys
   :identity (st/->st-var-bytes st/st-ushort-be)
   :obfuscated-ticket-age st/st-uint-be))

(def st-psk-identity-list
  (-> (st/->st-var-bytes st/st-ushort-be)
      (st/wrap-many-struct st-psk-identity)))

(def st-psk-binder-entry (st/->st-var-bytes st/st-ubyte))
(def st-psk-binder-entry-list
  (-> (st/->st-var-bytes st/st-ushort-be)
      (st/wrap-many-struct st-psk-binder-entry)))

(def st-offered-psks
  (st/keys
   :identities st-psk-identity-list
   :binders st-psk-binder-entry-list))

(def st-extension-pre-shared-key-client-hello st-offered-psks)
(def st-extension-pre-shared-key-server-hello st/st-ushort-be)

;;;;; server name

(def name-type-host-name 0)

(def st-name-type st/st-ubyte)

(def st-host-name (-> (st/->st-var-bytes st/st-ushort-be) st/wrap-str))

(def st-name
  (fn [{:keys [name-type]}]
    (condp = name-type
      name-type-host-name st-host-name
      (throw (ex-info "invalid name type" {:reason ::invalid-name-type :name-type name-type})))))

(def st-server-name
  (st/keys
   :name-type st-name-type
   :name st-name))

(def st-server-name-list
  (-> (st/->st-var-bytes st/st-ushort-be)
      (st/wrap-many-struct st-server-name)))

(def st-extension-server-name-client-hello st-server-name-list)
(def st-extension-server-name-server-hello st/st-null)

;;;;; alpn

(def st-protocol-name (-> (st/->st-var-bytes st/st-ubyte) st/wrap-str))
(def st-protocol-name-list
  (-> (st/->st-var-bytes st/st-ushort-be)
      (st/wrap-many-struct st-protocol-name)))

(def st-extension-application-layer-protocol-negotiation st-protocol-name-list)

;;; crypto

;;;; cipher suites

(def cipher-suite-map-base-sha256
  {:digest-fn       crypto/sha256
   :digest-size     32
   :hmac-fn         crypto/hmac-sha256
   :hkdf-fn         crypto/hkdf-sha256
   :hkdf-expand-fn  crypto/hkdf-expand-sha256
   :hkdf-extract-fn crypto/hkdf-extract-sha256})

(def cipher-suite-map-base-sha384
  {:digest-fn       crypto/sha384
   :digest-size     48
   :hmac-fn         crypto/hmac-sha384
   :hkdf-fn         crypto/hkdf-sha384
   :hkdf-expand-fn  crypto/hkdf-expand-sha384
   :hkdf-extract-fn crypto/hkdf-extract-sha384})

(def cipher-suite-map-tls-aes-128-gcm-sha256
  (merge
   cipher-suite-map-base-sha256
   {:aead-encrypt-fn crypto/aesgcm-encrypt
    :aead-decrypt-fn crypto/aesgcm-decrypt
    :aead-key-size   16
    :aead-iv-size    12
    :aead-tag-size   16}))

(def cipher-suite-map-tls-aes-256-gcm-sha384
  (merge
   cipher-suite-map-base-sha384
   {:aead-encrypt-fn crypto/aesgcm-encrypt
    :aead-decrypt-fn crypto/aesgcm-decrypt
    :aead-key-size   32
    :aead-iv-size    12
    :aead-tag-size   16}))

(def cipher-suite-map-tls-chacha20-poly1305-sha256
  (merge
   cipher-suite-map-base-sha256
   {:aead-encrypt-fn crypto/chacha20poly1305-encrypt
    :aead-decrypt-fn crypto/chacha20poly1305-decrypt
    :aead-key-size   32
    :aead-iv-size    12
    :aead-tag-size   16}))

(def cipher-suite-map
  {cipher-suite-tls-aes-128-gcm-sha256       cipher-suite-map-tls-aes-128-gcm-sha256
   cipher-suite-tls-aes-256-gcm-sha384       cipher-suite-map-tls-aes-256-gcm-sha384
   cipher-suite-tls-chacha20-poly1305-sha256 cipher-suite-map-tls-chacha20-poly1305-sha256})

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

;;;; cryptor

(defn ->cryptor
  "Construct cryptor."
  [cipher-suite ^bytes secret]
  (let [{:keys [aead-key-size aead-iv-size]} (get-cipher-suite cipher-suite)
        key (hkdf-expand-label cipher-suite secret label-key (byte-array 0) aead-key-size)
        iv (hkdf-expand-label cipher-suite secret label-iv (byte-array 0) aead-iv-size)]
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
        secret (hkdf-expand-label cipher-suite secret label-key-update (byte-array 0) digest-size)]
    (->cryptor cipher-suite secret)))

;;;; named groups

(def named-group-map-secp256r1
  {:gen-fn        crypto/secp256r1-gen
   :agreement-fn  crypto/secp256r1-agreement
   :pub->bytes-fn ecf/secp256r1-pub->bytes
   :bytes->pub-fn ecf/bytes->secp256r1-pub})

(def named-group-map-secp384r1
  {:gen-fn        crypto/secp384r1-gen
   :agreement-fn  crypto/secp384r1-agreement
   :pub->bytes-fn ecf/secp384r1-pub->bytes
   :bytes->pub-fn ecf/bytes->secp384r1-pub})

(def named-group-map-secp521r1
  {:gen-fn        crypto/secp521r1-gen
   :agreement-fn  crypto/secp521r1-agreement
   :pub->bytes-fn ecf/secp521r1-pub->bytes
   :bytes->pub-fn ecf/bytes->secp521r1-pub})

(def named-group-map-x25519
  {:gen-fn        crypto/x25519-gen
   :agreement-fn  crypto/x25519-agreement
   :pub->bytes-fn ecf/x25519-pub->bytes
   :bytes->pub-fn ecf/bytes->x25519-pub})

(def named-group-map-x448
  {:gen-fn        crypto/x448-gen
   :agreement-fn  crypto/x448-agreement
   :pub->bytes-fn ecf/x448-pub->bytes
   :bytes->pub-fn ecf/bytes->x448-pub})

(def named-group-map
  {named-group-secp256r1 named-group-map-secp256r1
   named-group-secp384r1 named-group-map-secp384r1
   named-group-secp521r1 named-group-map-secp521r1
   named-group-x25519    named-group-map-x25519
   named-group-x448      named-group-map-x448})

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

;;;; signature schemes

(def signature-scheme-map-ed25519                {:sign-fn crypto/ed25519-sign             :verify-fn crypto/ed25519-verify})
(def signature-scheme-map-ed448                  {:sign-fn crypto/ed448-sign               :verify-fn crypto/ed448-verify})
(def signature-scheme-map-ecdsa-secp256r1-sha256 {:sign-fn crypto/secp256r1-sha256-sign    :verify-fn crypto/secp256r1-sha256-verify})
(def signature-scheme-map-ecdsa-secp384r1-sha384 {:sign-fn crypto/secp384r1-sha384-sign    :verify-fn crypto/secp384r1-sha384-verify})
(def signature-scheme-map-ecdsa-secp521r1-sha512 {:sign-fn crypto/secp521r1-sha512-sign    :verify-fn crypto/secp521r1-sha512-verify})
(def signature-scheme-map-rsa-pss-rsae-sha256    {:sign-fn crypto/rsa-pss-rsae-sha256-sign :verify-fn crypto/rsa-pss-rsae-sha256-verify})
(def signature-scheme-map-rsa-pss-rsae-sha384    {:sign-fn crypto/rsa-pss-rsae-sha384-sign :verify-fn crypto/rsa-pss-rsae-sha384-verify})
(def signature-scheme-map-rsa-pss-rsae-sha512    {:sign-fn crypto/rsa-pss-rsae-sha512-sign :verify-fn crypto/rsa-pss-rsae-sha512-verify})
(def signature-scheme-map-rsa-pkcs1-sha256       {:sign-fn crypto/rsa-pkcs1-sha256-sign    :verify-fn crypto/rsa-pkcs1-sha256-verify})
(def signature-scheme-map-rsa-pkcs1-sha384       {:sign-fn crypto/rsa-pkcs1-sha384-sign    :verify-fn crypto/rsa-pkcs1-sha384-verify})
(def signature-scheme-map-rsa-pkcs1-sha512       {:sign-fn crypto/rsa-pkcs1-sha512-sign    :verify-fn crypto/rsa-pkcs1-sha512-verify})

(def signature-scheme-map
  {signature-scheme-ed25519                signature-scheme-map-ed25519
   signature-scheme-ed448                  signature-scheme-map-ed448
   signature-scheme-ecdsa-secp256r1-sha256 signature-scheme-map-ecdsa-secp256r1-sha256
   signature-scheme-ecdsa-secp384r1-sha384 signature-scheme-map-ecdsa-secp384r1-sha384
   signature-scheme-ecdsa-secp521r1-sha512 signature-scheme-map-ecdsa-secp521r1-sha512
   signature-scheme-rsa-pss-rsae-sha256    signature-scheme-map-rsa-pss-rsae-sha256
   signature-scheme-rsa-pss-rsae-sha384    signature-scheme-map-rsa-pss-rsae-sha384
   signature-scheme-rsa-pss-rsae-sha512    signature-scheme-map-rsa-pss-rsae-sha512
   signature-scheme-rsa-pkcs1-sha256       signature-scheme-map-rsa-pkcs1-sha256
   signature-scheme-rsa-pkcs1-sha384       signature-scheme-map-rsa-pkcs1-sha384
   signature-scheme-rsa-pkcs1-sha512       signature-scheme-map-rsa-pkcs1-sha512})

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

(def rsa-signature-schemes
  #{signature-scheme-rsa-pss-rsae-sha256
    signature-scheme-rsa-pss-rsae-sha384
    signature-scheme-rsa-pss-rsae-sha512
    signature-scheme-rsa-pkcs1-sha256
    signature-scheme-rsa-pkcs1-sha384
    signature-scheme-rsa-pkcs1-sha512})

(def pub-signature-schemes-map
  {:ed25519   #{signature-scheme-ed25519}
   :ed448     #{signature-scheme-ed448}
   :secp256r1 #{signature-scheme-ecdsa-secp256r1-sha256}
   :secp384r1 #{signature-scheme-ecdsa-secp384r1-sha384}
   :secp521r1 #{signature-scheme-ecdsa-secp521r1-sha512}
   :rsa-2048  rsa-signature-schemes
   :rsa-3072  rsa-signature-schemes
   :rsa-4096  rsa-signature-schemes})

(defn pub->signature-schemes
  "Convert public key to signature schemes."
  [^PublicKey pub]
  (let [type (crypto/pub->type pub)]
    (or (get pub-signature-schemes-map type)
        (throw (ex-info "invalid public key type" {:reason ::invalid-public-key-type :public-key-type type})))))

;;;; key schedule

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
  (let [derived (derive-secret cipher-suite early-secret label-derived nil)]
    (hkdf-extract cipher-suite shared-secret derived)))

;; client hello ... server hello
(defn client-handshake-secret
  "Expand client handshake secret."
  ^bytes [cipher-suite ^bytes handshake-secret msgs]
  (derive-secret cipher-suite handshake-secret label-client-handshake msgs))

;; client hello ... server hello
(defn server-handshake-secret
  "Expand server handshake secret."
  ^bytes [cipher-suite ^bytes handshake-secret msgs]
  (derive-secret cipher-suite handshake-secret label-server-handshake msgs))

(defn handshake-verify-key
  "Expand handshake verify key."
  ^bytes [cipher-suite ^bytes handshake-secret]
  (let [digest-size (digest-size cipher-suite)]
    (hkdf-expand-label cipher-suite handshake-secret label-finished (byte-array 0) digest-size)))

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
        derived (derive-secret cipher-suite handshake-secret label-derived nil)]
    (hkdf-extract cipher-suite (byte-array digest-size) derived)))

;; client hello ... server finished
(defn client-application-secret
  "Expand client application secret."
  ^bytes [cipher-suite ^bytes master-secret msgs]
  (derive-secret cipher-suite master-secret label-client-application msgs))

;; client hello ... server finished
(defn server-application-secret
  "Expand server application secret."
  ^bytes [cipher-suite ^bytes master-secret msgs]
  (derive-secret cipher-suite master-secret label-server-application msgs))

;;; context

(def default-signature-algorithms
  [signature-scheme-ed25519
   signature-scheme-ed448
   signature-scheme-ecdsa-secp256r1-sha256
   signature-scheme-ecdsa-secp384r1-sha384
   signature-scheme-ecdsa-secp521r1-sha512
   signature-scheme-rsa-pss-rsae-sha256
   signature-scheme-rsa-pss-rsae-sha384
   signature-scheme-rsa-pss-rsae-sha512
   signature-scheme-rsa-pkcs1-sha256
   signature-scheme-rsa-pkcs1-sha384
   signature-scheme-rsa-pkcs1-sha512])

(def default-cipher-suites
  [cipher-suite-tls-aes-128-gcm-sha256
   cipher-suite-tls-aes-256-gcm-sha384
   cipher-suite-tls-chacha20-poly1305-sha256])

(def default-named-groups
  [named-group-x25519
   named-group-x448
   named-group-secp256r1
   named-group-secp384r1
   named-group-secp521r1])

(def default-named-group
  named-group-x25519)

(def default-client-opts
  {:mode                 :client
   :stage                :wait-server-hello
   :signature-algorithms default-signature-algorithms
   :cipher-suites        default-cipher-suites
   :named-groups         [default-named-group]})

(def default-server-opts
  {:mode                 :server
   :stage                :wait-client-hello
   :signature-algorithms default-signature-algorithms
   :cipher-suites        default-cipher-suites
   :named-groups         default-named-groups})

(defmulti recv-record
  "Recv record, return new context."
  (fn [context _type _content] (:stage context)))

(defn pack-extension
  "Pack extension."
  [context extensions-key type extension]
  (update context extensions-key vec-conj {:extension-type type :extension-data extension}))

(defn find-extension
  "Find extension."
  [context extensions-key type]
  (->> (get context extensions-key) (filter #(= type (:extension-type %))) first :extension-data))

(defn send-plaintext
  "Send plaintext."
  [context type content]
  (let [record (st/pack st-record {:type type :version version-tls12 :content content})]
    (update context :send-bytes vec-conj record)))

(defn encrypt-record
  "Encrypt record, return new cryptor and ciphertext with header."
  [cryptor type content]
  (let [aead-tag-size (aead-tag-size cryptor)
        plaintext (pack-inner-plaintext type content)
        header (st/pack st-record-header
                        {:type content-type-application-data
                         :version version-tls12
                         :length (+ aead-tag-size (b/length plaintext))})
        [cryptor ciphertext] (encrypt cryptor plaintext header)]
    [cryptor (b/cat header ciphertext)]))

(defn decrypt-record
  "Decrypt record, return new cryptor, type and content."
  [cryptor ciphertext]
  (let [header (st/pack st-record-header
                        {:type content-type-application-data
                         :version version-tls12
                         :length (b/length ciphertext)})
        [cryptor plaintext] (decrypt cryptor ciphertext header)
        [type content] (unpack-inner-plaintext plaintext)]
    [cryptor type content]))

(defn send-ciphertext
  "Send ciphertext."
  [context encryptor-key type content]
  (let [encryptor (get context encryptor-key)
        [encryptor record] (encrypt-record encryptor type content)]
    (-> context
        (assoc encryptor-key encryptor)
        (update :send-bytes vec-conj record))))

(defn recv-ciphertext
  "Recv ciphertext, return new context and decrypted type, content."
  [context decryptor-key content]
  (let [decryptor (get context decryptor-key)
        [decryptor type content] (decrypt-record decryptor content)
        context (assoc context decryptor-key decryptor)]
    [context type content]))

(defn send-handshake-plaintext
  "Send handshake plaintext."
  [context msg-type msg-data]
  (let [handshake (st/pack st-handshake {:msg-type msg-type :msg-data msg-data})]
    (-> context
        (update :handshake-msgs vec-conj handshake)
        (send-plaintext content-type-handshake handshake))))

(defn send-handshake-ciphertext
  "Send handshake ciphertext."
  [context msg-type msg-data]
  (let [handshake (st/pack st-handshake {:msg-type msg-type :msg-data msg-data})]
    (-> context
        (update :handshake-msgs vec-conj handshake)
        (send-ciphertext :handshake-encryptor content-type-handshake handshake))))

(defn recv-handshake-plaintext
  "Recv handshake plaintext, return new context, msg type and msg data."
  ([context type content]
   (condp = type
     content-type-handshake
     (recv-handshake-plaintext context content)
     (throw (ex-info "invalid content type" {:reason ::invalid-content-type :content-type type}))))
  ([context content]
   (let [context (update context :handshake-msgs vec-conj content)
         {:keys [msg-type msg-data]} (st/unpack st-handshake content)]
     [context msg-type msg-data])))

(defn recv-handshake-ciphertext
  "Recv handshake ciphertext, return new context, msg type and msg data."
  ([context type content]
   (condp = type
     content-type-application-data
     (recv-handshake-ciphertext context content)
     (throw (ex-info "invalid content type" {:reason ::invalid-content-type :content-type type}))))
  ([context content]
   (let [[context type content] (recv-ciphertext context :handshake-decryptor content)]
     (recv-handshake-plaintext context type content))))

(defn send-application-ciphertext
  "Send application ciphertext."
  [context type content]
  (send-ciphertext context :application-encryptor type content))

(defn recv-application-ciphertext
  "Recv application ciphertext."
  ([context type content]
   (condp = type
     content-type-application-data
     (recv-application-ciphertext context content)
     (throw (ex-info "invalid content type" {:reason ::invalid-content-type :content-type type}))))
  ([context content]
   (recv-ciphertext context :application-decryptor content)))

(defn recv-alert
  "Recv alert."
  [content]
  (let [{:keys [level description]} (st/unpack st-alert content)]
    (throw (ex-info "alert" {:reason ::alert :level level :description description}))))

(defn send-change-cipher-spec
  "Send change cipher spec."
  [context]
  (cond-> context
    (get context :send-change-cipher-spec? true)
    (send-plaintext
     content-type-change-cipher-spec
     (st/pack st-change-cipher-spec change-ciper-spec))))

(defn recv-change-cipher-spec
  "Recv change cipher spec."
  [context content]
  (let [change-cipher-spec (st/unpack st-change-cipher-spec content)]
    (if (= change-cipher-spec change-ciper-spec)
      context
      (throw (ex-info "invalid change cipher spec" {:reason ::invalid-change-cipher-spec :change-cipher-spec change-cipher-spec})))))

(defn recv-change-cipher-spec-maybe
  "Maybe recv change cipher spec, or goto next stage."
  [context type content next-stage]
  (condp = type
    content-type-application-data
    (-> context
        (merge {:stage next-stage})
        (recv-record type content))
    content-type-change-cipher-spec
    (-> context
        (merge {:stage next-stage})
        (recv-change-cipher-spec content))
    (throw (ex-info "invalid content type" {:reason ::invalid-content-type :content-type type}))))

(defn init-early-secret
  "Init early secret."
  [{:keys [cipher-suite] :as context}]
  (merge context {:early-secret (early-secret cipher-suite)}))

(defn init-handshake-secret
  "Init handshake secret."
  [{:keys [mode cipher-suite early-secret shared-secret handshake-msgs] :as context}]
  (let [handshake-secret (handshake-secret cipher-suite early-secret shared-secret)
        client-handshake-secret (client-handshake-secret cipher-suite handshake-secret handshake-msgs)
        server-handshake-secret (server-handshake-secret cipher-suite handshake-secret handshake-msgs)
        handshake-encryptor (->cryptor cipher-suite (case mode :client client-handshake-secret :server server-handshake-secret))
        handshake-decryptor (->cryptor cipher-suite (case mode :client server-handshake-secret :server client-handshake-secret))]
    (merge
     context
     {:handshake-secret handshake-secret
      :client-handshake-secret client-handshake-secret
      :server-handshake-secret server-handshake-secret
      :handshake-encryptor handshake-encryptor
      :handshake-decryptor handshake-decryptor})))

(defn init-master-secret
  "Init master secret."
  [{:keys [mode cipher-suite handshake-secret handshake-msgs] :as context}]
  (let [master-secret (master-secret cipher-suite handshake-secret)
        client-application-secret (client-application-secret cipher-suite master-secret handshake-msgs)
        server-application-secret (server-application-secret cipher-suite master-secret handshake-msgs)
        application-encryptor (->cryptor cipher-suite (case mode :client client-application-secret :server server-application-secret))
        application-decryptor (->cryptor cipher-suite (case mode :client server-application-secret :server client-application-secret))]
    (merge
     context
     {:master-secret master-secret
      :client-application-secret client-application-secret
      :server-application-secret server-application-secret
      :application-decryptor application-decryptor
      :application-encryptor application-encryptor})))

(defn unpack-extension-signature-algorithms
  "Unpack signature algorithms extension."
  [context extension]
  (let [signature-algorithms (st/unpack st-extension-signature-algorithms extension)
        {:keys [mode]} context
        [certificate-list-key signature-algorithm-key]
        (case mode
          :client [:client-certificate-list :client-signature-algorithm]
          :server [:server-certificate-list :server-signature-algorithm])]
    (if-let [certificate (-> context (get certificate-list-key) first :certificate)]
      (let [supported-signature-algorithms (set/intersection
                                            (set (:signature-algorithms context))
                                            (-> certificate ks/cert->pub pub->signature-schemes))]
        (if-let [signature-algorithm (->> signature-algorithms (some supported-signature-algorithms))]
          (assoc context signature-algorithm-key signature-algorithm)
          (throw (ex-info "invalid signature algorithms" {:reason ::invalid-signature-algorithms :signature-algorithms signature-algorithms}))))
      (throw (ex-info "require auth" {:reason ::require-auth})))))

(defn send-certificate
  "Send certificate."
  [context]
  (let [{:keys [mode]} context
        certificate-list-key (case mode :client :client-certificate-list :server :server-certificate-list)]
    (send-handshake-ciphertext
     context handshake-type-certificate
     (st/pack st-handshake-certificate
              {:certificate-request-context (byte-array 0)
               :certificate-list (->> (get context certificate-list-key)
                                      (map
                                       (fn [{:keys [certificate extensions]}]
                                         {:cert-data (ks/cert->bytes certificate)
                                          :extensions extensions})))}))))

(defn send-certificate-verify
  "Send certificate verify."
  [context]
  (let [{:keys [mode cipher-suite handshake-msgs]} context
        [private-key signature-algorithm-key signature-context-string]
        (case mode
          :client [:client-private-key :client-signature-algorithm client-signature-context-string]
          :server [:server-private-key :server-signature-algorithm server-signature-context-string])
        private-key (get context private-key)
        signature-algorithm (get context signature-algorithm-key)
        signature-data (pack-signature-data signature-context-string (apply digest cipher-suite handshake-msgs))
        signature (sign signature-algorithm private-key signature-data)]
    (send-handshake-ciphertext
     context handshake-type-certificate-verify
     (st/pack st-handshake-certificate-verify {:algorithm signature-algorithm :signature signature}))))

;; limited: only accept self-signed certificate by default

(defn verify-certificate-list
  "Verify certificate list."
  [context]
  (if-not (get context :verify-certificate-list? true)
    context
    (let [{:keys [mode ca-certificate-list]} context
          certificate-list-key (case mode :client :server-certificate-list :server :client-certificate-list)
          certificate-list (->> (get context certificate-list-key) (map :certificate))]
      (if (and (= 1 (count certificate-list))
               (->> ca-certificate-list (some (partial = (last certificate-list)))))
        context
        (throw (ex-info "invalid certificate list" {:reason ::invalid-certificate-list}))))))

(defn recv-certificate-plaintext
  "Recv certificate plaintext."
  ([context msg-type msg-data]
   (condp = msg-type
     handshake-type-certificate
     (recv-certificate-plaintext context msg-data)
     (throw (ex-info "invalid handshake type" {:reason ::invalid-handshake-type :handshake-type msg-type}))))
  ([context msg-data]
   (let [{:keys [mode]} context
         {:keys [certificate-list]} (st/unpack st-handshake-certificate msg-data)
         certificate-list-key (case mode :client :server-certificate-list :server :client-certificate-list)
         certificate-list (->> certificate-list
                               (mapv
                                (fn [{:keys [cert-data extensions]}]
                                  {:certificate (ks/bytes->cert cert-data)
                                   :extensions extensions})))]
     (-> context
         (assoc certificate-list-key certificate-list)
         verify-certificate-list))))

(defn recv-certificate
  "Recv certificate."
  [context type content]
  (let [[context msg-type msg-data] (recv-handshake-ciphertext context type content)]
    (recv-certificate-plaintext context msg-type msg-data)))

(defn recv-certificate-verify
  "Recv certificate verify."
  [context type content]
  (let [[context msg-type msg-data] (recv-handshake-ciphertext context type content)]
    (condp = msg-type
      handshake-type-certificate-verify
      (let [{:keys [mode cipher-suite signature-algorithms handshake-msgs]} context
            [certificate-list-key signature-algorithm-key signature-context-string]
            (case mode
              :client [:server-certificate-list :server-signature-algorithm server-signature-context-string]
              :server [:client-certificate-list :client-signature-algorithm client-signature-context-string])
            certificate (-> context (get certificate-list-key) first :certificate)
            {:keys [algorithm signature]} (st/unpack st-handshake-certificate-verify msg-data)]
        (if (contains? (set signature-algorithms) algorithm)
          (let [signature-data (pack-signature-data signature-context-string (apply digest cipher-suite (butlast handshake-msgs)))]
            (if (verify algorithm (ks/cert->pub certificate) signature-data signature)
              (assoc context signature-algorithm-key algorithm)
              (throw (ex-info "invalid signature" {:reason ::invalid-signature}))))
          (throw (ex-info "invalid signature algorithm" {:reason ::invalid-signature-algorithm :signature-algorithm algorithm}))))
      (throw (ex-info "invalid handshake type" {:reason ::invalid-handshake-type :handshake-type msg-type})))))

(defn send-finished
  "Send finished."
  [context]
  (let [{:keys [mode cipher-suite handshake-msgs]} context
        handshake-secret-key (case mode :client :client-handshake-secret :server :server-handshake-secret)
        verify (handshake-verify cipher-suite (get context handshake-secret-key) handshake-msgs)]
    (send-handshake-ciphertext context handshake-type-finished verify)))

(defn verify-finished
  "Verify finished."
  [context msg-data]
  (let [{:keys [mode cipher-suite handshake-msgs]} context
        handshake-secret-key (case mode :client :server-handshake-secret :server :client-handshake-secret)
        verify (handshake-verify cipher-suite (get context handshake-secret-key) (butlast handshake-msgs))]
    (if (zero? (b/compare msg-data verify))
      context
      (throw (ex-info "invalid finished" {:reason ::invalid-finished})))))

;;;; client

;;;;; client hello

(defn init-client-key-shares
  "Init client key shares."
  [context]
  (let [{:keys [named-groups]} context
        key-shares (->> named-groups (mapv gen-key-share))]
    (merge context {:key-shares key-shares})))

(defn pack-client-extension-supported-versions
  "Pack supported versions extension."
  [context]
  (pack-extension
   context :client-extensions
   extension-type-supported-versions
   (st/pack st-extension-supported-versions-client-hello [version-tls13])))

(defn pack-client-extension-signature-algorithms
  "Pack signature algorithms extension."
  [{:keys [signature-algorithms] :as context}]
  (pack-extension
   context :client-extensions
   extension-type-signature-algorithms
   (st/pack st-extension-signature-algorithms signature-algorithms)))

(defn pack-client-extension-supported-groups
  "Pack supported groups extension."
  [{:keys [named-groups] :as context}]
  (pack-extension
   context :client-extensions
   extension-type-supported-groups
   (st/pack st-extension-supported-groups named-groups)))

(defn pack-client-extension-key-share
  "Pack key share extension."
  [{:keys [key-shares] :as context}]
  (pack-extension
   context :client-extensions
   extension-type-key-share
   (st/pack st-extension-key-share-client-hello
            (->> key-shares
                 (map
                  (fn [{:keys [named-group] :as key-share}]
                    {:group named-group :key-exchange (key-share->pub-bytes key-share)}))))))

(defn pack-client-extension-server-name
  "Pack server name extension."
  [{:keys [server-names] :as context}]
  (cond-> context
    (seq server-names)
    (pack-extension
     :client-extensions
     extension-type-server-name
     (st/pack st-extension-server-name-client-hello
              (->> server-names
                   (map
                    (fn [server-name]
                      {:name-type name-type-host-name :name server-name})))))))

(defn pack-client-extension-application-layer-protocol-negotiation
  "Pack application layer protocol negotiation extension."
  [{:keys [application-protocols] :as context}]
  (cond-> context
    (seq application-protocols)
    (pack-extension
     :client-extensions
     extension-type-application-layer-protocol-negotiation
     (st/pack st-extension-application-layer-protocol-negotiation application-protocols))))

(defn send-client-hello
  "Send client hello."
  [context]
  (let [{:keys [cipher-suites client-extensions]} context]
    (send-handshake-plaintext
     context
     handshake-type-client-hello
     (st/pack st-handshake-client-hello
              {:legacy-version version-tls12
               :random (b/rand 32)
               :legacy-session-id (b/rand 32)
               :cipher-suites cipher-suites
               :legacy-compression-methods [compression-method-null]
               :extensions client-extensions}))))

(defn ->client-context
  "Construct initial client context."
  [opts]
  (-> (merge default-client-opts opts)
      init-client-key-shares
      pack-client-extension-supported-versions
      pack-client-extension-signature-algorithms
      pack-client-extension-supported-groups
      pack-client-extension-key-share
      pack-client-extension-server-name
      pack-client-extension-application-layer-protocol-negotiation
      send-client-hello))

;;;;; server hello

(defn unpack-server-extension-supported-versions
  "Unpack supported versions extension."
  [context]
  (if-let [extension (find-extension context :server-extensions extension-type-supported-versions)]
    (let [selected-version (st/unpack st-extension-supported-versions-server-hello extension)]
      (if (= selected-version version-tls13)
        context
        (throw (ex-info "invalid version" {:reason ::invalid-version :version selected-version}))))
    (throw (ex-info "no selected version" {:reason ::no-selected-version}))))

(defn unpack-server-extension-key-share
  "Unpack key share extension."
  [{:keys [key-shares] :as context}]
  (if-let [extension (find-extension context :server-extensions extension-type-key-share)]
    (let [{:keys [key-exchange] selected-named-group :group}
          (st/unpack st-extension-key-share-server-hello extension)]
      (if-let [key-share (->> key-shares (filter #(= selected-named-group (:named-group %))) first)]
        (let [shared-secret (key-agreement key-share key-exchange)]
          (merge context {:named-group selected-named-group :shared-secret shared-secret}))
        (throw (ex-info "invalid named group" {:reason ::invalid-named-group :named-group selected-named-group}))))
    (throw (ex-info "no selected key share" {:reason ::no-selected-key-share}))))

(defmethod recv-record :wait-server-hello [context type content]
  (if (= type content-type-alert)
    ;; throw client hello params error
    (recv-alert content)
    (let [[context msg-type msg-data] (recv-handshake-plaintext context type content)]
      (condp = msg-type
        handshake-type-server-hello
        (let [{:keys [cipher-suites]} context
              {:keys [random cipher-suite extensions]} (st/unpack st-handshake-server-hello msg-data)]
          (if (contains? (set cipher-suites) cipher-suite)
            (-> context
                (merge
                 {:stage :wait-server-ccs-ee
                  :cipher-suite cipher-suite
                  :server-extensions extensions})
                unpack-server-extension-supported-versions
                unpack-server-extension-key-share
                init-early-secret
                init-handshake-secret)
            (throw (ex-info "invalid cipher suite" {:reason ::invalid-cipher-suite :cipher-suite cipher-suite}))))
        (throw (ex-info "invalid handshake type" {:reason ::invalid-handshake-type :handshake-type msg-type}))))))

;;;;; server encrypted extensions

(defmethod recv-record :wait-server-ccs-ee [context type content]
  (recv-change-cipher-spec-maybe context type content :wait-server-ee))

(defn unpack-server-encrypted-extension-server-name
  "Unpack server name extension."
  [context]
  (cond-> context
    (some? (find-extension context :server-encrypted-extensions extension-type-application-layer-protocol-negotiation))
    (merge {:accept-server-name? true})))

(defn unpack-server-encrypted-extension-application-layer-protocol-negotiation
  "Unpack application layer protocol negotiation extension."
  [{:keys [application-protocols] :as context}]
  (if-let [extension (find-extension context :server-encrypted-extensions extension-type-application-layer-protocol-negotiation)]
    (let [selected-application-protocols (st/unpack st-extension-application-layer-protocol-negotiation extension)]
      (if (= 1 (count selected-application-protocols))
        (let [selected-application-protocol (first selected-application-protocols)]
          (if (contains? (set application-protocols) selected-application-protocol)
            (merge context {:application-protocol selected-application-protocol})
            (throw (ex-info "invalid application protocols" {:reason ::invalid-applicatoin-protocols :application-protocols selected-application-protocols}))))
        (throw (ex-info "invalid application protocols" {:reason ::invalid-applicatoin-protocols :application-protocols selected-application-protocols}))))
    context))

(defmethod recv-record :wait-server-ee [context type content]
  (let [[context msg-type msg-data] (recv-handshake-ciphertext context type content)]
    (condp = msg-type
      handshake-type-encrypted-extensions
      (let [extensions (st/unpack st-handshake-encrypted-extensions msg-data)]
        (-> context
            (merge {:stage :wait-server-cert-cr :server-encrypted-extensions extensions})
            unpack-server-encrypted-extension-server-name
            unpack-server-encrypted-extension-application-layer-protocol-negotiation))
      (throw (ex-info "invalid handshake type" {:reason ::invalid-handshake-type :handshake-type msg-type})))))

;;;;; server certificate

(defn unpack-server-certificate-request-extension-signature-algorithms
  "Unpack signature algorithms extension."
  [context]
  (if-let [extension (find-extension context :server-certificate-request-extensions extension-type-signature-algorithms)]
    (unpack-extension-signature-algorithms context extension)
    (throw (ex-info "no signature algorithms" {:reason ::no-signature-algorithms}))))

(defmethod recv-record :wait-server-cert-cr [context type content]
  (let [[context msg-type msg-data] (recv-handshake-ciphertext context type content)]
    (if (= msg-type handshake-type-certificate-request)
      (let [{:keys [extensions]} (st/unpack st-handshake-certificate-request msg-data)]
        (-> context
            (merge {:stage :wait-server-cert :client-auth? true :server-certificate-request-extensions extensions})
            unpack-server-certificate-request-extension-signature-algorithms))
      (-> context
          (merge {:stage :wait-server-cv})
          (recv-certificate-plaintext msg-type msg-data)))))

(defmethod recv-record :wait-server-cert [context type content]
  (-> context
      (merge {:stage :wait-server-cv})
      (recv-certificate type content)))

(defmethod recv-record :wait-server-cv [context type content]
  (-> context
      (merge {:stage :wait-server-finished})
      (recv-certificate-verify type content)))

;;;;; server finished

(defn send-client-certificate-maybe
  "Send certificate."
  [context]
  (cond-> context
    (:client-auth? context) send-certificate))

(defn send-client-certificate-verify-maybe
  "Send certificate verify."
  [context]
  (cond-> context
    (:client-auth? context) send-certificate-verify))

(defmethod recv-record :wait-server-finished [context type content]
  (let [[context msg-type msg-data] (recv-handshake-ciphertext context type content)]
    (condp = msg-type
      handshake-type-finished
      (-> context
          (merge {:stage :connected})
          (verify-finished msg-data)
          init-master-secret
          send-change-cipher-spec
          send-client-certificate-maybe
          send-client-certificate-verify-maybe
          send-finished)
      (throw (ex-info "invalid handshake type" {:reason ::invalid-handshake-type :handshake-type msg-type})))))

;;;; server

;;;;; client hello

(defn ->server-context
  "Construct server context."
  [opts]
  (merge default-server-opts opts))

(defn unpack-client-extension-supported-versions
  "Unpack supported versions extension."
  [context]
  (if-let [extension (find-extension context :client-extensions extension-type-supported-versions)]
    (let [supported-versions (st/unpack st-extension-supported-versions-client-hello extension)]
      (if (contains? (set supported-versions) version-tls13)
        context
        (throw (ex-info "invalid versions" {:reason ::invalid-versions :versions supported-versions}))))
    (throw (ex-info "no supported versions" {:reason ::no-supported-versions}))))

(defn unpack-client-extension-signature-algorithms
  "Unpack signature algorithms extension."
  [context]
  (if-let [extension (find-extension context :client-extensions extension-type-signature-algorithms)]
    (unpack-extension-signature-algorithms context extension)
    (throw (ex-info "no signature algorithms" {:reason ::no-signature-algorithms}))))

(defn unpack-client-extension-key-share
  "Unpack key share extension."
  [context]
  (if-let [extension (find-extension context :client-extensions extension-type-key-share)]
    (let [server-named-groups (set (:named-groups context))
          supported-key-shares (st/unpack st-extension-key-share-client-hello extension)]
      (if-let [{:keys [key-exchange] selected-named-group :group}
               (->> supported-key-shares (filter #(contains? server-named-groups (:group %))) first)]
        (let [key-share (gen-key-share selected-named-group)
              shared-secret (key-agreement key-share key-exchange)]
          (merge context {:key-share key-share :named-group selected-named-group :shared-secret shared-secret}))
        (throw (ex-info "invalid key shares" {:reason ::invalid-named-groups :named-groups (->> supported-key-shares (mapv :group))}))))
    (throw (ex-info "no supported key shares" {:reason ::no-supported-key-shares}))))

(defn unpack-client-extension-server-name
  "Unpack server name extension."
  [context]
  (if-let [extension (find-extension context :client-extensions extension-type-server-name)]
    (let [server-names (->> (st/unpack st-extension-server-name-client-hello extension) (map :name))]
      (merge context {:server-names server-names}))
    context))

(defn unpack-client-extension-application-layer-protocol-negotiation
  "Unpack application layer protocol negotiation extension."
  [context]
  (if (seq (:application-protocols context))
    (if-let [extension (find-extension context :client-extensions extension-type-application-layer-protocol-negotiation)]
      (let [server-application-protocols (set (:application-protocols context))
            supported-application-protocols (st/unpack st-extension-application-layer-protocol-negotiation extension)]
        (if-let [selected-application-protocol (->> supported-application-protocols (some server-application-protocols))]
          (merge context {:application-protocol selected-application-protocol})
          (throw (ex-info "invalid application protocols" {:reason ::invalid-applicatoin-protocols :application-protocols supported-application-protocols}))))
      context)
    context))

(defn pack-server-extension-supported-versions
  "Pack supported versions extension."
  [context]
  (pack-extension
   context :server-extensions
   extension-type-supported-versions
   (st/pack st-extension-supported-versions-server-hello version-tls13)))

(defn pack-server-extension-key-share
  "Pack key share extension."
  [{:keys [key-share named-group] :as context}]
  (pack-extension
   context :server-extensions
   extension-type-key-share
   (st/pack st-extension-key-share-server-hello
            {:group named-group :key-exchange (key-share->pub-bytes key-share)})))

(defn pack-server-encrypted-extension-server-name
  "Pack server name extension."
  [{:keys [server-names] :as context}]
  (cond-> context
    (some? server-names)
    (pack-extension
     :server-encrypted-extensions
     extension-type-server-name (byte-array 0))))

(defn pack-server-encrypted-extension-application-layer-protocol-negotiation
  "Pack application layer protocol negotiation extension."
  [{:keys [application-protocol] :as context}]
  (cond-> context
    (some? application-protocol)
    (pack-extension
     :server-encrypted-extensions
     extension-type-application-layer-protocol-negotiation
     (st/pack st-extension-application-layer-protocol-negotiation [application-protocol]))))

(defn send-server-hello
  "Send server hello."
  [context]
  (let [{:keys [cipher-suite server-extensions legacy-session-id]} context]
    (send-handshake-plaintext
     context
     handshake-type-server-hello
     (st/pack st-handshake-server-hello
              {:legacy-version version-tls12
               :random (b/rand 32)
               :legacy-session-id-echo legacy-session-id
               :cipher-suite cipher-suite
               :legacy-compression-method compression-method-null
               :extensions server-extensions}))))

(defn send-server-encrypted-extensions
  "Send encrypted extensions."
  [context]
  (let [{:keys [server-encrypted-extensions]} context]
    (send-handshake-ciphertext
     context handshake-type-encrypted-extensions
     (st/pack st-handshake-encrypted-extensions server-encrypted-extensions))))

(defn pack-server-certificate-request-extension-signature-algorithms-maybe
  "Pack signature algorithms extension."
  [{:keys [signature-algorithms] :as context}]
  (cond-> context
    (:client-auth? context)
    (pack-extension
     :server-certificate-request-extensions
     extension-type-signature-algorithms
     (st/pack st-extension-signature-algorithms signature-algorithms))))

(defn send-server-certificate-request-maybe
  "Send certificate request."
  [context]
  (let [{:keys [server-certificate-request-extensions]} context]
    (cond-> context
      (:client-auth? context)
      (send-handshake-ciphertext
       handshake-type-certificate-request
       (st/pack st-handshake-certificate-request
                {:certificate-request-context (byte-array 0)
                 :extensions server-certificate-request-extensions})))))

(defmethod recv-record :wait-client-hello [context type content]
  (let [[context msg-type msg-data] (recv-handshake-plaintext context type content)]
    (condp = msg-type
      handshake-type-client-hello
      (let [{:keys [client-auth?]} context
            server-cipher-suites (set (:cipher-suites context))
            {:keys [random cipher-suites extensions legacy-session-id]} (st/unpack st-handshake-client-hello msg-data)]
        (if-let [cipher-suite (->> cipher-suites (some server-cipher-suites))]
          (-> context
              (merge
               {:stage (if client-auth? :wait-client-ccs-cert :wait-client-ccs-finished)
                :cipher-suite cipher-suite
                :client-extensions extensions
                :legacy-session-id legacy-session-id})
              unpack-client-extension-supported-versions
              unpack-client-extension-signature-algorithms
              unpack-client-extension-key-share
              unpack-client-extension-server-name
              unpack-client-extension-application-layer-protocol-negotiation
              pack-server-extension-supported-versions
              pack-server-extension-key-share
              pack-server-encrypted-extension-server-name
              pack-server-encrypted-extension-application-layer-protocol-negotiation
              send-server-hello
              init-early-secret
              init-handshake-secret
              send-change-cipher-spec
              send-server-encrypted-extensions
              pack-server-certificate-request-extension-signature-algorithms-maybe
              send-server-certificate-request-maybe
              send-certificate
              send-certificate-verify
              send-finished
              init-master-secret)
          (throw (ex-info "invalid cipher suites" {:reason ::invalid-cipher-suites :cipher-suites cipher-suites}))))
      (throw (ex-info "invalid handshake type" {:reason ::invalid-handshake-type :handshake-type msg-type})))))

;;;;; client certificate

(defmethod recv-record :wait-client-ccs-cert [context type content]
  (recv-change-cipher-spec-maybe context type content :wait-client-cert))

(defmethod recv-record :wait-client-cert [context type content]
  (-> context
      (merge {:stage :wait-client-cv})
      (recv-certificate type content)))

(defmethod recv-record :wait-client-cv [context type content]
  (-> context
      (merge {:stage :wait-client-finished})
      (recv-certificate-verify type content)))

;;;;; client finished

(defmethod recv-record :wait-client-ccs-finished [context type content]
  (recv-change-cipher-spec-maybe context type content :wait-client-finished))

(defmethod recv-record :wait-client-finished [context type content]
  (let [[context msg-type msg-data] (recv-handshake-ciphertext context type content)]
    (condp = msg-type
      handshake-type-finished
      (-> context
          (merge {:stage :connected})
          (verify-finished msg-data))
      (throw (ex-info "invalid handshake type" {:reason ::invalid-handshake-type :handshake-type msg-type})))))

;;;; connection

(defn recv-application-alert
  "Recv application alert."
  [context content]
  (let [{:keys [level description]} (st/unpack st-alert content)]
    (if (and (= level alert-level-warning)
             (= description alert-description-close-notify))
      (assoc context :read-close? true)
      (throw (ex-info "alert" {:reason ::alert :level level :description description})))))

(defn recv-new-session-ticket
  "Recv new session ticket."
  [context msg-data]
  (merge context {:new-session-ticket (st/unpack st-handshake-new-session-ticket msg-data)}))

(defn recv-key-update
  "Recv key update."
  [context msg-data]
  (let [key-update (st/unpack st-handshake-key-update msg-data)]
    (condp = key-update
      key-update-not-requested
      (update context :application-decryptor update-key)
      key-update-requested
      ;; set key update flag
      (merge context {:key-update? true})
      (throw (ex-info "invalid key update" {:reason ::invalid-key-update :key-update key-update})))))

(defn recv-application-handshake
  "Recv application handshake."
  [context content]
  (let [{:keys [msg-type msg-data]} (st/unpack st-handshake content)]
    (condp = msg-type
      handshake-type-new-session-ticket
      (recv-new-session-ticket context msg-data)
      handshake-type-key-update
      (recv-key-update context msg-data)
      (throw (ex-info "invalid handshake type" {:reason ::invalid-handshake-type :handshake-type msg-type})))))

(defmethod recv-record :connected [context type content]
  (if (:read-close? context)
    (throw (ex-info "read data surplus" {:reason ::read-data-surplus}))
    (let [[context type content] (recv-application-ciphertext context type content)]
      (condp = type
        content-type-application-data
        (update context :recv-bytes vec-conj content)
        content-type-alert
        (recv-application-alert context content)
        content-type-handshake
        (recv-application-handshake context content)
        (throw (ex-info "invalid content type" {:reason ::invalid-content-type :content-type type}))))))

(defn check-writable
  "Check context writable."
  [{:keys [stage write-close?] :as context}]
  (if (and (= stage :connected) (not write-close?))
    context
    (throw (ex-info "write data surplus" {:reason ::write-data-surplus}))))

(defn send-data
  "Send data."
  [context content]
  (-> context
      check-writable
      (send-application-ciphertext content-type-application-data content)))

(defn send-close-notify
  "Send close notify."
  [context]
  (-> context
      check-writable
      (merge {:write-close? true})
      (send-application-ciphertext
       content-type-alert
       (st/pack st-alert
                {:level alert-level-warning
                 :description alert-description-close-notify}))))

(defn send-key-update
  "Send key update."
  [context]
  (-> context
      check-writable
      (send-application-ciphertext
       content-type-handshake
       (st/pack st-handshake
                {:msg-type handshake-type-key-update
                 :msg-data (st/pack st-handshake-key-update key-update-not-requested)}))
      (update :application-encryptor update-key)
      ;; reset key update flag
      (merge {:key-update? false})))

(defn send-key-update-request
  "Send key update request."
  [context]
  (-> context
      check-writable
      (send-application-ciphertext
       content-type-handshake
       (st/pack st-handshake
                {:msg-type handshake-type-key-update
                 :msg-data (st/pack st-handshake-key-update key-update-requested)}))))

;;; stream

(defn handshake
  "Do handshake on stream, return new context."
  [{is :input-stream os :output-stream} context]
  (loop [context context]
    (let [{:keys [stage send-bytes]} context]
      (if (seq send-bytes)
        (do
          (run! (partial st/write os) send-bytes)
          (st/flush os)
          (recur (dissoc context :send-bytes)))
        (if (= stage :connected)
          context
          (let [{:keys [type content]} (st/read-struct st-record is)]
            (recur (recv-record context type content))))))))

(defn wrap-input-stream
  "Wrap input stream."
  ^InputStream [^InputStream is acontext]
  (let [read-fn (fn []
                  (let [{:keys [recv-bytes read-close?]} @acontext]
                    (if (seq recv-bytes)
                      (do
                        (swap! acontext update :recv-bytes (partial vec-drop (count recv-bytes)))
                        (let [b (apply b/cat recv-bytes)]
                          (if-not (zero? (b/length b))
                            b
                            (recur))))
                      (when-not read-close?
                        (let [{:keys [type content]} (st/read-struct st-record is)]
                          (swap! acontext recv-record type content)
                          (recur))))))]
    (BufferedInputStream. (st/read-fn->input-stream read-fn #(st/close is)))))

(defn wrap-output-stream
  "Wrap output stream."
  ^OutputStream [^OutputStream os acontext]
  (let [write-fn (fn [b]
                   (when-not (zero? (b/length b))
                     (when (:key-update? @acontext)
                       (swap! acontext send-key-update))
                     (swap! acontext send-data b)
                     (let [{:keys [send-bytes]} @acontext]
                       (when (seq send-bytes)
                         (swap! acontext update :send-bytes (partial vec-drop (count send-bytes)))
                         (run! (partial st/write os) send-bytes)
                         (st/flush os)))))
        close-fn (fn []
                   (swap! acontext send-close-notify)
                   (let [{:keys [send-bytes]} @acontext]
                     (when (seq send-bytes)
                       (swap! acontext update :send-bytes (partial vec-drop (count send-bytes)))
                       (run! (partial st/write os) send-bytes)
                       (st/flush os))
                     (st/close os)))]
    (BufferedOutputStream. (st/write-fn->output-stream write-fn close-fn))))

(defn mk-stream
  "Wrap tls13 on stream."
  [{is :input-stream os :output-stream :as stream} context callback]
  (let [context (handshake stream context)
        acontext (atom context)]
    (with-open [is (wrap-input-stream is acontext)
                os (wrap-output-stream os acontext)]
      (callback {:acontext acontext :input-stream is :output-stream os}))))

(defn mk-client
  "Make tls13 client."
  [server opts callback]
  (let [{:keys [key-store trust-store]} opts
        ca-certificate-list (:certs trust-store)
        client-certificate-list (->> (:certs key-store) (map (fn [certificate] {:certificate certificate})))
        client-private-key (:pri key-store)
        opts (merge
              opts
              {:ca-certificate-list ca-certificate-list
               :client-certificate-list client-certificate-list
               :client-private-key client-private-key})
        context (->client-context opts)]
    (mk-stream server context callback)))

(defn mk-server
  "Make tls13 server."
  [client opts callback]
  (let [{:keys [key-store trust-store]} opts
        ca-certificate-list (:certs trust-store)
        server-certificate-list (->> (:certs key-store) (map (fn [certificate] {:certificate certificate})))
        server-private-key (:pri key-store)
        opts (merge
              opts
              {:ca-certificate-list ca-certificate-list
               :server-certificate-list server-certificate-list
               :server-private-key server-private-key})
        context (->server-context opts)]
    (mk-stream client context callback)))
