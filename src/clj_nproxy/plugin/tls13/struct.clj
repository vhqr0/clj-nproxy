(ns clj-nproxy.plugin.tls13.struct
  "TLS 1.3 struct definitions."
  (:require [clj-nproxy.bytes :as b]
            [clj-nproxy.struct :as st]))

;; RFC 8446 TLS 1.3
;; RFC 6066 TLS Extensions
;; RFC 7301 TLS ALPN Extensions

(set! clojure.core/*warn-on-reflection* true)

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

;;; const

;;;; label

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

;;;; version

(def version-ssl30 0x0300)
(def version-tls10 0x0301)
(def version-tls11 0x0302)
(def version-tls12 0x0303)
(def version-tls13 0x0304)

(def st-protocol-version st/st-ushort-be)
(def st-protocol-version-list
  (-> (st/->st-var-bytes st/st-ubyte)
      (st/wrap-many-struct st-protocol-version)))

;;;; compression

(def compression-method-null 0)

(def st-compression-method st/st-ubyte)
(def st-compression-method-list
  (-> (st/->st-var-bytes st/st-ubyte)
      (st/wrap-many-struct st-compression-method)))

;;;; signature scheme

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

;;;; cipher suite

(def cipher-suite-tls-aes-128-gcm-sha256       0x1301)
(def cipher-suite-tls-aes-256-gcm-sha384       0x1302)
(def cipher-suite-tls-chacha20-poly1305-sha256 0x1303)
(def cipher-suite-tls-aes-128-ccm-sha256       0x1304)
(def cipher-suite-tls-aes-128-ccm-8-sha256     0x1305)

(def st-cipher-suite st/st-ushort-be)
(def st-cipher-suite-list
  (-> (st/->st-var-bytes st/st-ushort-be)
      (st/wrap-many-struct st-cipher-suite)))

;;;; named group

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

;;; record

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

;;;; change cipher spec

(def change-ciper-spec 1)

(def st-change-cipher-spec st/st-ubyte)

;;;; alert

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

;;; handshake

;;;; extension

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

;;;; handshake

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

;;;; supported versions

(def st-extension-supported-versions-client-hello st-protocol-version-list)
(def st-extension-supported-versions-server-hello st-protocol-version)

;;;; cookie

(def st-extension-cookie (st/->st-var-bytes st/st-ushort-be))

;;;; signature algorithms

(def st-extension-signature-algorithms st-signature-scheme-list)

;;;; certificate authorities

(def st-distinguished-name (st/->st-var-bytes st/st-ushort-be))
(def st-distinguished-name-list
  (-> (st/->st-var-bytes st/st-ushort-be)
      (st/wrap-many-struct st-distinguished-name)))

(def st-extension-certificate-authorities st-distinguished-name-list)

;;;; oid filters

(def st-oid-filter
  (st/keys
   :certificate-extension-oid (st/->st-var-bytes st/st-ubyte)
   :certificate-extension-values (st/->st-var-bytes st/st-ushort-be)))

(def st-oid-filter-list
  (-> (st/->st-var-bytes st/st-ushort-be)
      (st/wrap-many-struct st-oid-filter)))

(def st-extension-oid-filters st-oid-filter-list)

;;;; post handshake auth

(def st-extension-post-handshake-auth st/st-null)

;;;; supported groups

(def st-extension-supported-groups st-named-group-list)

;;;; key share

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

;;;; psk key exchange modes

(def psk-key-exchange-mode-ke     0)
(def psk-key-exchange-mode-dhe-ke 1)

(def st-psk-key-exchange-mode st/st-ubyte)
(def st-psk-key-exchange-mode-list
  (-> (st/->st-var-bytes st/st-ubyte)
      (st/wrap-many-struct st-psk-key-exchange-mode)))

(def st-extension-psk-key-exchange-modes st-psk-key-exchange-mode-list)

;;;; early data

(def st-extension-early-data-new-session-ticket st/st-uint-be)
(def st-extension-early-data-client-hello st/st-null)
(def st-extension-early-data-encrypted-extensions st/st-null)

;;;; pre shared key

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

;;;; server name

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

;;;; alpn

(def st-protocol-name (-> (st/->st-var-bytes st/st-ubyte) st/wrap-str))
(def st-protocol-name-list
  (-> (st/->st-var-bytes st/st-ushort-be)
      (st/wrap-many-struct st-protocol-name)))

(def st-extension-application-layer-protocol-negotiation st-protocol-name-list)
