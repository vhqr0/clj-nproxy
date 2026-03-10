(ns clj-nproxy.plugin.tls13.context
  "TLS 1.3 context logic."
  (:require [clojure.set :as set]
            [clj-nproxy.bytes :as b]
            [clj-nproxy.struct :as st]
            [clj-nproxy.crypto.keystore :as ks]
            [clj-nproxy.plugin.tls13.struct :as tls13-st]
            [clj-nproxy.plugin.tls13.crypto :as tls13-crypto]))

(set! clojure.core/*warn-on-reflection* true)

(def default-signature-algorithms
  [tls13-st/signature-scheme-ed25519
   tls13-st/signature-scheme-ed448
   tls13-st/signature-scheme-ecdsa-secp256r1-sha256
   tls13-st/signature-scheme-ecdsa-secp384r1-sha384
   tls13-st/signature-scheme-ecdsa-secp521r1-sha512
   tls13-st/signature-scheme-rsa-pss-rsae-sha256
   tls13-st/signature-scheme-rsa-pss-rsae-sha384
   tls13-st/signature-scheme-rsa-pss-rsae-sha512
   tls13-st/signature-scheme-rsa-pkcs1-sha256
   tls13-st/signature-scheme-rsa-pkcs1-sha384
   tls13-st/signature-scheme-rsa-pkcs1-sha512])

(def default-cipher-suites
  [tls13-st/cipher-suite-tls-aes-128-gcm-sha256
   tls13-st/cipher-suite-tls-aes-256-gcm-sha384
   tls13-st/cipher-suite-tls-chacha20-poly1305-sha256])

(def default-named-groups
  [tls13-st/named-group-x25519
   tls13-st/named-group-x448
   tls13-st/named-group-secp256r1
   tls13-st/named-group-secp384r1
   tls13-st/named-group-secp521r1])

(def default-named-group
  tls13-st/named-group-x25519)

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

(def vec-conj (fnil conj []))

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
  (let [record (st/pack tls13-st/st-record {:type type :version tls13-st/version-tls12 :content content})]
    (update context :send-bytes vec-conj record)))

(defn encrypt-record
  "Encrypt record, return new cryptor and ciphertext with header."
  [cryptor type content]
  (let [aead-tag-size (tls13-crypto/aead-tag-size cryptor)
        plaintext (tls13-st/pack-inner-plaintext type content)
        header (st/pack tls13-st/st-record-header
                        {:type tls13-st/content-type-application-data
                         :version tls13-st/version-tls12
                         :length (+ aead-tag-size (b/length plaintext))})
        [cryptor ciphertext] (tls13-crypto/encrypt cryptor plaintext header)]
    [cryptor (b/cat header ciphertext)]))

(defn decrypt-record
  "Decrypt record, return new cryptor, type and content."
  [cryptor ciphertext]
  (let [header (st/pack tls13-st/st-record-header
                        {:type tls13-st/content-type-application-data
                         :version tls13-st/version-tls12
                         :length (b/length ciphertext)})
        [cryptor plaintext] (tls13-crypto/decrypt cryptor ciphertext header)
        [type content] (tls13-st/unpack-inner-plaintext plaintext)]
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
  (let [handshake (st/pack tls13-st/st-handshake {:msg-type msg-type :msg-data msg-data})]
    (-> context
        (update :handshake-msgs vec-conj handshake)
        (send-plaintext tls13-st/content-type-handshake handshake))))

(defn send-handshake-ciphertext
  "Send handshake ciphertext."
  [context msg-type msg-data]
  (let [handshake (st/pack tls13-st/st-handshake {:msg-type msg-type :msg-data msg-data})]
    (-> context
        (update :handshake-msgs vec-conj handshake)
        (send-ciphertext :handshake-encryptor tls13-st/content-type-handshake handshake))))

(defn recv-handshake-plaintext
  "Recv handshake plaintext, return new context, msg type and msg data."
  ([context type content]
   (condp = type
     tls13-st/content-type-handshake
     (recv-handshake-plaintext context content)
     (throw (ex-info "invalid content type" {:reason ::invalid-content-type :content-type type}))))
  ([context content]
   (let [context (update context :handshake-msgs vec-conj content)
         {:keys [msg-type msg-data]} (st/unpack tls13-st/st-handshake content)]
     [context msg-type msg-data])))

(defn recv-handshake-ciphertext
  "Recv handshake ciphertext, return new context, msg type and msg data."
  ([context type content]
   (condp = type
     tls13-st/content-type-application-data
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
     tls13-st/content-type-application-data
     (recv-application-ciphertext context content)
     (throw (ex-info "invalid content type" {:reason ::invalid-content-type :content-type type}))))
  ([context content]
   (recv-ciphertext context :application-decryptor content)))

(defn recv-alert
  "Recv alert."
  [content]
  (let [{:keys [level description]} (st/unpack tls13-st/st-alert content)]
    (throw (ex-info "alert" {:reason ::alert :level level :description description}))))

(defn send-change-cipher-spec
  "Send change cipher spec."
  [context]
  (send-plaintext
   context
   tls13-st/content-type-change-cipher-spec
   (st/pack tls13-st/st-change-cipher-spec tls13-st/change-ciper-spec)))

(defn recv-change-cipher-spec
  "Recv change cipher spec."
  [context content]
  (let [change-cipher-spec (st/unpack tls13-st/st-change-cipher-spec content)]
    (if (= change-cipher-spec tls13-st/change-ciper-spec)
      context
      (throw (ex-info "invalid change cipher spec" {:reason ::invalid-change-cipher-spec :change-cipher-spec change-cipher-spec})))))

(defn recv-change-cipher-spec-maybe
  "Maybe recv change cipher spec, or goto next stage."
  [context type content next-stage]
  (condp = type
    tls13-st/content-type-application-data
    (-> context
        (merge {:stage next-stage})
        (recv-record type content))
    tls13-st/content-type-change-cipher-spec
    (-> context
        (merge {:stage next-stage})
        (recv-change-cipher-spec content))
    (throw (ex-info "invalid content type" {:reason ::invalid-content-type :content-type type}))))

(defn init-random
  "Init random."
  [{:keys [mode] :as context}]
  (let [random-key (case mode :client :client-random :server :server-random)]
    (assoc context random-key (b/rand 32))))

(defn init-early-secret
  "Init early secret."
  [{:keys [cipher-suite] :as context}]
  (merge context {:early-secret (tls13-crypto/early-secret cipher-suite)}))

(defn init-handshake-secret
  "Init handshake secret."
  [{:keys [mode cipher-suite early-secret shared-secret handshake-msgs] :as context}]
  (let [digest-size (tls13-crypto/digest-size cipher-suite)
        handshake-secret (tls13-crypto/handshake-secret cipher-suite early-secret shared-secret)
        client-handshake-secret (tls13-crypto/client-handshake-secret cipher-suite handshake-secret handshake-msgs)
        server-handshake-secret (tls13-crypto/server-handshake-secret cipher-suite handshake-secret handshake-msgs)
        client-handshake-verify-key (tls13-crypto/hkdf-expand-label cipher-suite client-handshake-secret tls13-st/label-finished (byte-array 0) digest-size)
        server-handshake-verify-key (tls13-crypto/hkdf-expand-label cipher-suite server-handshake-secret tls13-st/label-finished (byte-array 0) digest-size)
        handshake-encryptor (tls13-crypto/->cryptor cipher-suite (case mode :client client-handshake-secret :server server-handshake-secret))
        handshake-decryptor (tls13-crypto/->cryptor cipher-suite (case mode :client server-handshake-secret :server client-handshake-secret))]
    (merge
     context
     {:handshake-secret handshake-secret
      :client-handshake-secret client-handshake-secret
      :server-handshake-secret server-handshake-secret
      :client-handshake-verify-key client-handshake-verify-key
      :server-handshake-verify-key server-handshake-verify-key
      :handshake-encryptor handshake-encryptor
      :handshake-decryptor handshake-decryptor})))

(defn init-master-secret
  "Init master secret."
  [{:keys [mode cipher-suite handshake-secret handshake-msgs] :as context}]
  (let [master-secret (tls13-crypto/master-secret cipher-suite handshake-secret)
        client-application-secret (tls13-crypto/client-application-secret cipher-suite master-secret handshake-msgs)
        server-application-secret (tls13-crypto/server-application-secret cipher-suite master-secret handshake-msgs)
        application-encryptor (tls13-crypto/->cryptor cipher-suite (case mode :client client-application-secret :server server-application-secret))
        application-decryptor (tls13-crypto/->cryptor cipher-suite (case mode :client server-application-secret :server client-application-secret))]
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
  (let [signature-algorithms (st/unpack tls13-st/st-extension-signature-algorithms extension)
        {:keys [mode]} context
        [certificate-list-key signature-algorithm-key]
        (case mode
          :client [:client-certificate-list :client-signature-algorithm]
          :server [:server-certificate-list :server-signature-algorithm])
        certificate (-> context (get certificate-list-key) first :certificate)
        supported-signature-algorithms (set/intersection
                                        (set (:signature-algorithms context))
                                        (-> certificate tls13-crypto/cert->pub tls13-crypto/pub->signature-schemes))]
    (if-let [signature-algorithm (->> signature-algorithms (some supported-signature-algorithms))]
      (assoc context signature-algorithm-key signature-algorithm)
      (throw (ex-info "invalid signature algorithms" {:reason ::invalid-signature-algorithms :signature-algorithms signature-algorithms})))))

(defn send-certificate
  "Send certificate."
  [context]
  (let [{:keys [mode]} context
        certificate-list-key (case mode
                               :client :client-certificate-list
                               :server :server-certificate-list)]
    (send-handshake-ciphertext
     context tls13-st/handshake-type-certificate
     (st/pack tls13-st/st-handshake-certificate
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
        [certificate-list-key private-key signature-algorithm-key]
        (case mode
          :client [:client-certificate-list :client-private-key :client-signature-algorithm]
          :server [:server-certificate-list :server-private-key :server-signature-algorithm])
        certificate (-> context (get certificate-list-key) first :certificate)
        private-key (get context private-key)
        signature-algorithm (get context signature-algorithm-key)
        signature-data (tls13-st/pack-signature-data
                        (case mode
                          :client tls13-st/client-signature-context-string
                          :server tls13-st/server-signature-context-string)
                        (apply tls13-crypto/digest cipher-suite handshake-msgs))
        signature (tls13-crypto/sign signature-algorithm private-key signature-data)]
    (send-handshake-ciphertext
     context tls13-st/handshake-type-certificate-verify
     (st/pack tls13-st/st-handshake-certificate-verify {:algorithm signature-algorithm :signature signature}))))

(defn send-auth
  "Send auth."
  [context]
  (-> context send-certificate send-certificate-verify))

;; limited: only accept self-signed certificate by default

(defn verify-certificate-list
  "Verify certificate list."
  [context certificate-list]
  (let [{:keys [verify-certificate-list? ca-certificate-list max-certificate-path]
         :or {verify-certificate-list? true max-certificate-path 1}} context
        certificate-chain (->> certificate-list (map :certificate))]
    (if-not verify-certificate-list?
      context
      (if (seq certificate-chain)
        (if (<= (count certificate-chain) max-certificate-path)
          (if (tls13-crypto/verify-cert-chain certificate-chain)
            (if (->> ca-certificate-list (some (partial = (last certificate-chain))))
              context
              (throw (ex-info "invalid ca certificate" {:reason ::invalid-ca-certificate-list})))
            (throw (ex-info "invalid certificate chain" {:reason ::invalid-certificate-chain})))
          (throw (ex-info "invalid certificate path" {:reason ::invalid-certificate-path})))
        (throw (ex-info "empty certificate chain" {:reason ::empty-certificate-chain}))))))

(defn recv-certificate-plaintext
  "Recv certificate plaintext."
  ([context msg-type msg-data]
   (condp = msg-type
     tls13-st/handshake-type-certificate
     (recv-certificate-plaintext context msg-data)
     (throw (ex-info "invalid handshake type" {:reason ::invalid-handshake-type :handshake-type msg-type}))))
  ([context msg-data]
   (let [{:keys [mode]} context
         {:keys [certificate-list]} (st/unpack tls13-st/st-handshake-certificate msg-data)
         certificate-list-key (case mode :client :server-certificate-list :server :client-certificate-list)
         certificate-list (->> certificate-list
                               (mapv
                                (fn [{:keys [cert-data extensions]}]
                                  {:certificate (ks/bytes->cert cert-data)
                                   :extensions extensions})))]
     (-> context
         (verify-certificate-list certificate-list)
         (assoc certificate-list-key certificate-list)))))

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
      tls13-st/handshake-type-certificate-verify
      (let [{:keys [mode cipher-suite signature-algorithms handshake-msgs]} context
            [certificate-list-key signature-algorithm-key signature-context-string]
            (case mode
              :client [:server-certificate-list :server-signature-algorithm tls13-st/server-signature-context-string]
              :server [:client-certificate-list :client-signature-algorithm tls13-st/client-signature-context-string])
            certificate (-> context (get certificate-list-key) first :certificate)
            {:keys [algorithm signature]} (st/unpack tls13-st/st-handshake-certificate-verify msg-data)]
        (if (contains? (set signature-algorithms) algorithm)
          (let [signature-data (tls13-st/pack-signature-data signature-context-string (apply tls13-crypto/digest cipher-suite (butlast handshake-msgs)))]
            (if (tls13-crypto/verify algorithm (tls13-crypto/cert->pub certificate) signature-data signature)
              (assoc context signature-algorithm-key algorithm)
              (throw (ex-info "invalid signature" {:reason ::invalid-signature}))))
          (throw (ex-info "invalid signature algorithm" {:reason ::invalid-signature-algorithm :signature-algorithm algorithm}))))
      (throw (ex-info "invalid handshake type" {:reason ::invalid-handshake-type :handshake-type msg-type})))))

(defn send-finished
  "Send finished."
  [{:keys [mode cipher-suite handshake-msgs] :as context}]
  (let [verify (tls13-crypto/hmac cipher-suite
                                  (case mode
                                    :client (:client-handshake-verify-key context)
                                    :server (:server-handshake-verify-key context))
                                  (apply tls13-crypto/digest cipher-suite handshake-msgs))]
    (send-handshake-ciphertext context tls13-st/handshake-type-finished verify)))

(defn verify-finished
  "Verify finished."
  [context msg-data]
  (let [{:keys [mode cipher-suite handshake-msgs]} context
        verify (tls13-crypto/hmac cipher-suite
                                  (case mode
                                    :client (:server-handshake-verify-key context)
                                    :server (:client-handshake-verify-key context))
                                  (apply tls13-crypto/digest cipher-suite (butlast handshake-msgs)))]
    (if (zero? (b/compare msg-data verify))
      context
      (throw (ex-info "invalid finished" {:reason ::invalid-finished})))))

;;; client

;;;; client hello

(defn init-client-key-shares
  "Init client key shares."
  [context]
  (let [{:keys [named-groups]} context
        key-shares (->> named-groups (mapv tls13-crypto/gen-key-share))]
    (merge context {:key-shares key-shares})))

(defn pack-client-extension-supported-versions
  "Pack supported versions extension."
  [context]
  (pack-extension
   context :client-extensions
   tls13-st/extension-type-supported-versions
   (st/pack tls13-st/st-extension-supported-versions-client-hello [tls13-st/version-tls13])))

(defn pack-client-extension-signature-algorithms
  "Pack signature algorithms extension."
  [{:keys [signature-algorithms] :as context}]
  (pack-extension
   context :client-extensions
   tls13-st/extension-type-signature-algorithms
   (st/pack tls13-st/st-extension-signature-algorithms signature-algorithms)))

(defn pack-client-extension-supported-groups
  "Pack supported groups extension."
  [{:keys [named-groups] :as context}]
  (pack-extension
   context :client-extensions
   tls13-st/extension-type-supported-groups
   (st/pack tls13-st/st-extension-supported-groups named-groups)))

(defn pack-client-extension-key-share
  "Pack key share extension."
  [{:keys [key-shares] :as context}]
  (pack-extension
   context :client-extensions
   tls13-st/extension-type-key-share
   (st/pack tls13-st/st-extension-key-share-client-hello
            (->> key-shares
                 (map
                  (fn [{:keys [named-group] :as key-share}]
                    {:group named-group :key-exchange (tls13-crypto/key-share->pub-bytes key-share)}))))))

(defn pack-client-extension-server-name
  "Pack server name extension."
  [{:keys [server-names] :as context}]
  (cond-> context
    (seq server-names)
    (pack-extension
     :client-extensions
     tls13-st/extension-type-server-name
     (st/pack tls13-st/st-extension-server-name-client-hello
              (->> server-names
                   (map
                    (fn [server-name]
                      {:name-type tls13-st/name-type-host-name :name server-name})))))))

(defn pack-client-extension-application-layer-protocol-negotiation
  "Pack application layer protocol negotiation extension."
  [{:keys [application-protocols] :as context}]
  (cond-> context
    (seq application-protocols)
    (pack-extension
     :client-extensions
     tls13-st/extension-type-application-layer-protocol-negotiation
     (st/pack tls13-st/st-extension-application-layer-protocol-negotiation application-protocols))))

(defn send-client-hello
  "Send client hello."
  [context]
  (let [{:keys [client-random cipher-suites client-extensions]} context]
    (send-handshake-plaintext
     context
     tls13-st/handshake-type-client-hello
     (st/pack tls13-st/st-handshake-client-hello
              {:legacy-version tls13-st/version-tls12
               :random client-random
               :legacy-session-id (byte-array 0)
               :cipher-suites cipher-suites
               :legacy-compression-methods [tls13-st/compression-method-null]
               :extensions client-extensions}))))

(defn ->client-context
  "Construct initial client context."
  [opts]
  (-> (merge default-client-opts opts)
      init-random
      init-client-key-shares
      pack-client-extension-supported-versions
      pack-client-extension-signature-algorithms
      pack-client-extension-supported-groups
      pack-client-extension-key-share
      pack-client-extension-server-name
      pack-client-extension-application-layer-protocol-negotiation
      send-client-hello))

;;;; server hello

(defn unpack-server-extension-supported-versions
  "Unpack supported versions extension."
  [context]
  (if-let [extension (find-extension context :server-extensions tls13-st/extension-type-supported-versions)]
    (let [selected-version (st/unpack tls13-st/st-extension-supported-versions-server-hello extension)]
      (if (= selected-version tls13-st/version-tls13)
        context
        (throw (ex-info "invalid version" {:reason ::invalid-version :version selected-version}))))
    (throw (ex-info "no selected version" {:reason ::no-selected-version}))))

(defn unpack-server-extension-key-share
  "Unpack key share extension."
  [{:keys [key-shares] :as context}]
  (if-let [extension (find-extension context :server-extensions tls13-st/extension-type-key-share)]
    (let [{:keys [key-exchange] selected-named-group :group}
          (st/unpack tls13-st/st-extension-key-share-server-hello extension)]
      (if-let [key-share (->> key-shares (filter #(= selected-named-group (:named-group %))) first)]
        (let [shared-secret (tls13-crypto/key-agreement key-share key-exchange)]
          (merge context {:named-group selected-named-group :shared-secret shared-secret}))
        (throw (ex-info "invalid named group" {:reason ::invalid-named-group :named-group selected-named-group}))))
    (throw (ex-info "no selected key share" {:reason ::no-selected-key-share}))))

(defmethod recv-record :wait-server-hello [context type content]
  (if (= type tls13-st/content-type-alert)
    ;; throw client hello params error
    (recv-alert content)
    (let [[context msg-type msg-data] (recv-handshake-plaintext context type content)]
      (condp = msg-type
        tls13-st/handshake-type-server-hello
        (let [{:keys [cipher-suites]} context
              {:keys [random cipher-suite extensions]} (st/unpack tls13-st/st-handshake-server-hello msg-data)]
          (if (contains? (set cipher-suites) cipher-suite)
            (-> context
                (merge
                 {:stage :wait-server-ccs-ee
                  :cipher-suite cipher-suite
                  :server-random random
                  :server-extensions extensions})
                unpack-server-extension-supported-versions
                unpack-server-extension-key-share
                init-early-secret
                init-handshake-secret)
            (throw (ex-info "invalid cipher suite" {:reason ::invalid-cipher-suite :cipher-suite cipher-suite}))))
        (throw (ex-info "invalid handshake type" {:reason ::invalid-handshake-type :handshake-type msg-type}))))))

;;;; server encrypted extensions

(defmethod recv-record :wait-server-ccs-ee [context type content]
  (recv-change-cipher-spec-maybe context type content :wait-server-ee))

(defn unpack-server-encrypted-extension-server-name
  "Unpack server name extension."
  [context]
  (cond-> context
    (some? (find-extension context :server-encrypted-extensions tls13-st/extension-type-application-layer-protocol-negotiation))
    (merge {:accept-server-name? true})))

(defn unpack-server-encrypted-extension-application-layer-protocol-negotiation
  "Unpack application layer protocol negotiation extension."
  [{:keys [application-protocols] :as context}]
  (if-let [extension (find-extension context :server-encrypted-extensions tls13-st/extension-type-application-layer-protocol-negotiation)]
    (let [selected-application-protocols (st/unpack tls13-st/st-extension-application-layer-protocol-negotiation extension)]
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
      tls13-st/handshake-type-encrypted-extensions
      (let [extensions (st/unpack tls13-st/st-handshake-encrypted-extensions msg-data)]
        (-> context
            (merge {:stage :wait-server-cert-cr :server-encrypted-extensions extensions})
            unpack-server-encrypted-extension-server-name
            unpack-server-encrypted-extension-application-layer-protocol-negotiation))
      (throw (ex-info "invalid handshake type" {:reason ::invalid-handshake-type :handshake-type msg-type})))))

;;;; server certificate

(defn unpack-server-certificate-request-extension-signature-algorithms
  "Unpack signature algorithms extension."
  [context]
  (if-let [extension (find-extension context :server-certificate-request-extensions tls13-st/extension-type-signature-algorithms)]
    (unpack-extension-signature-algorithms context extension)
    (throw (ex-info "no signature algorithms" {:reason ::no-signature-algorithms}))))

(defmethod recv-record :wait-server-cert-cr [context type content]
  (let [[context msg-type msg-data] (recv-handshake-ciphertext context type content)]
    (if (= msg-type tls13-st/handshake-type-certificate-request)
      (let [{:keys [extensions]} (st/unpack tls13-st/st-handshake-certificate-request msg-data)]
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

;;;; server finished

(defn send-client-auth
  "Send client auth."
  [context]
  (if-not (:client-auth? context)
    context
    (if (and (:client-certificate-list context)
             (:client-private-key context))
      (send-auth context)
      (throw (ex-info "require client auth" {:reason ::require-client-auth})))))

(defmethod recv-record :wait-server-finished [context type content]
  (let [[context msg-type msg-data] (recv-handshake-ciphertext context type content)]
    (condp = msg-type
      tls13-st/handshake-type-finished
      (-> context
          (merge {:stage :connected})
          (verify-finished msg-data)
          send-change-cipher-spec
          send-client-auth
          send-finished
          init-master-secret)
      (throw (ex-info "invalid handshake type" {:reason ::invalid-handshake-type :handshake-type msg-type})))))

;;; server

;;;; client hello

(defn ->server-context
  "Construct server context."
  [opts]
  (merge default-server-opts opts))

(defn unpack-client-extension-supported-versions
  "Unpack supported versions extension."
  [context]
  (if-let [extension (find-extension context :client-extensions tls13-st/extension-type-supported-versions)]
    (let [supported-versions (st/unpack tls13-st/st-extension-supported-versions-client-hello extension)]
      (if (contains? (set supported-versions) tls13-st/version-tls13)
        context
        (throw (ex-info "invalid versions" {:reason ::invalid-versions :versions supported-versions}))))
    (throw (ex-info "no supported versions" {:reason ::no-supported-versions}))))

(defn unpack-client-extension-signature-algorithms
  "Unpack signature algorithms extension."
  [context]
  (if-let [extension (find-extension context :client-extensions tls13-st/extension-type-signature-algorithms)]
    (unpack-extension-signature-algorithms context extension)
    (throw (ex-info "no signature algorithms" {:reason ::no-signature-algorithms}))))

(defn unpack-client-extension-key-share
  "Unpack key share extension."
  [context]
  (if-let [extension (find-extension context :client-extensions tls13-st/extension-type-key-share)]
    (let [server-named-groups (set (:named-groups context))
          supported-key-shares (st/unpack tls13-st/st-extension-key-share-client-hello extension)]
      (if-let [{:keys [key-exchange] selected-named-group :group}
               (->> supported-key-shares (filter #(contains? server-named-groups (:group %))) first)]
        (let [key-share (tls13-crypto/gen-key-share selected-named-group)
              shared-secret (tls13-crypto/key-agreement key-share key-exchange)]
          (merge context {:key-share key-share :named-group selected-named-group :shared-secret shared-secret}))
        (throw (ex-info "invalid key shares" {:reason ::invalid-named-groups :named-groups (->> supported-key-shares (mapv :group))}))))
    (throw (ex-info "no supported key shares" {:reason ::no-supported-key-shares}))))

(defn unpack-client-extension-server-name
  "Unpack server name extension."
  [context]
  (if-let [extension (find-extension context :client-extensions tls13-st/extension-type-server-name)]
    (let [server-names (->> (st/unpack tls13-st/st-extension-server-name-client-hello extension) (map :name))]
      (merge context {:server-names server-names}))
    context))

(defn unpack-client-extension-application-layer-protocol-negotiation
  "Unpack application layer protocol negotiation extension."
  [context]
  (if (seq (:application-protocols context))
    (if-let [extension (find-extension context :client-extensions tls13-st/extension-type-application-layer-protocol-negotiation)]
      (let [server-application-protocols (set (:application-protocols context))
            supported-application-protocols (st/unpack tls13-st/st-extension-application-layer-protocol-negotiation extension)]
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
   tls13-st/extension-type-supported-versions
   (st/pack tls13-st/st-extension-supported-versions-server-hello tls13-st/version-tls13)))

(defn pack-server-extension-key-share
  "Pack key share extension."
  [{:keys [key-share named-group] :as context}]
  (pack-extension
   context :server-extensions
   tls13-st/extension-type-key-share
   (st/pack tls13-st/st-extension-key-share-server-hello
            {:group named-group :key-exchange (tls13-crypto/key-share->pub-bytes key-share)})))

(defn pack-server-encrypted-extension-server-name
  "Pack server name extension."
  [{:keys [server-names] :as context}]
  (cond-> context
    (some? server-names)
    (pack-extension
     :server-encrypted-extensions
     tls13-st/extension-type-server-name (byte-array 0))))

(defn pack-server-encrypted-extension-application-layer-protocol-negotiation
  "Pack application layer protocol negotiation extension."
  [{:keys [application-protocol] :as context}]
  (cond-> context
    (some? application-protocol)
    (pack-extension
     :server-encrypted-extensions
     tls13-st/extension-type-application-layer-protocol-negotiation
     (st/pack tls13-st/st-extension-application-layer-protocol-negotiation [application-protocol]))))

(defn send-server-hello
  "Send server hello."
  [context]
  (let [{:keys [server-random cipher-suite server-extensions legacy-session-id]} context]
    (send-handshake-plaintext
     context
     tls13-st/handshake-type-server-hello
     (st/pack tls13-st/st-handshake-server-hello
              {:legacy-version tls13-st/version-tls12
               :random server-random
               :legacy-session-id-echo legacy-session-id
               :cipher-suite cipher-suite
               :legacy-compression-method tls13-st/compression-method-null
               :extensions server-extensions}))))

(defn send-server-encrypted-extensions
  "Send encrypted extensions."
  [context]
  (let [{:keys [server-encrypted-extensions]} context]
    (send-handshake-ciphertext
     context tls13-st/handshake-type-encrypted-extensions
     (st/pack tls13-st/st-handshake-encrypted-extensions server-encrypted-extensions))))

(defn pack-server-certificate-request-extension-signature-algorithms
  "Pack signature algorithms extension."
  [{:keys [signature-algorithms] :as context}]
  (pack-extension
   context :server-certificate-request-extensions
   tls13-st/extension-type-signature-algorithms
   (st/pack tls13-st/st-extension-signature-algorithms signature-algorithms)))

(defn send-server-certificate-request
  "Send certificate request."
  [context]
  (let [{:keys [server-certificate-request-extensions]} context]
    (send-handshake-ciphertext
     context tls13-st/handshake-type-certificate-request
     (st/pack tls13-st/st-handshake-certificate-request
              {:certificate-request-context (byte-array 0)
               :extensions server-certificate-request-extensions}))))

(defn send-server-auth
  "Send server auth."
  [context]
  (let [{:keys [client-auth?]} context
        context (if-not client-auth?
                  context
                  (-> context
                      pack-server-certificate-request-extension-signature-algorithms
                      send-server-certificate-request))]
    (send-auth context)))

(defmethod recv-record :wait-client-hello [context type content]
  (let [[context msg-type msg-data] (recv-handshake-plaintext context type content)]
    (condp = msg-type
      tls13-st/handshake-type-client-hello
      (let [{:keys [client-auth?]} context
            server-cipher-suites (set (:cipher-suites context))
            {:keys [random cipher-suites extensions legacy-session-id]} (st/unpack tls13-st/st-handshake-client-hello msg-data)]
        (if-let [cipher-suite (->> cipher-suites (some server-cipher-suites))]
          (-> context
              (merge
               {:stage (if client-auth? :wait-client-ccs-cert :wait-client-ccs-finished)
                :cipher-suite cipher-suite
                :client-random random
                :client-extensions extensions
                :legacy-session-id legacy-session-id})
              init-random
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
              send-change-cipher-spec
              init-early-secret
              init-handshake-secret
              send-server-encrypted-extensions
              send-server-auth
              send-finished)
          (throw (ex-info "invalid cipher suites" {:reason ::invalid-cipher-suites :cipher-suites cipher-suites}))))
      (throw (ex-info "invalid handshake type" {:reason ::invalid-handshake-type :handshake-type msg-type})))))

;;;; client certificate

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

;;;; client finished

(defmethod recv-record :wait-client-ccs-finished [context type content]
  (recv-change-cipher-spec-maybe context type content :wait-client-finished))

(defmethod recv-record :wait-client-finished [context type content]
  (let [[context msg-type msg-data] (recv-handshake-ciphertext context type content)]
    (condp = msg-type
      tls13-st/handshake-type-finished
      (-> context
          (merge {:stage :connected})
          (verify-finished msg-data)
          init-master-secret)
      (throw (ex-info "invalid handshake type" {:reason ::invalid-handshake-type :handshake-type msg-type})))))

;;; connection

(defn recv-application-alert
  "Recv application alert."
  [context content]
  (let [{:keys [level description]} (st/unpack tls13-st/st-alert content)]
    (if (and (= level tls13-st/alert-level-warning)
             (= description tls13-st/alert-description-close-notify))
      (assoc context :read-close? true)
      (throw (ex-info "alert" {:reason ::alert :level level :description description})))))

(defn recv-new-session-ticket
  "Recv new session ticket."
  [context msg-data]
  (merge context {:new-session-ticket (st/unpack tls13-st/st-handshake-new-session-ticket msg-data)}))

(defn recv-key-update
  "Recv key update."
  [context msg-data]
  (let [key-update (st/unpack tls13-st/st-handshake-key-update msg-data)]
    (condp = key-update
      tls13-st/key-update-not-requested
      (update context :application-decryptor tls13-crypto/update-key)
      tls13-st/key-update-requested
      ;; set key update flag
      (merge context {:key-update? true})
      (throw (ex-info "invalid key update" {:reason ::invalid-key-update :key-update key-update})))))

(defn recv-application-handshake
  "Recv application handshake."
  [context content]
  (let [{:keys [msg-type msg-data]} (st/unpack tls13-st/st-handshake content)]
    (condp = msg-type
      tls13-st/handshake-type-new-session-ticket
      (recv-new-session-ticket context msg-data)
      tls13-st/handshake-type-key-update
      (recv-key-update context msg-data)
      (throw (ex-info "invalid handshake type" {:reason ::invalid-handshake-type :handshake-type msg-type})))))

(defmethod recv-record :connected [context type content]
  (if (:read-close? context)
    (throw (ex-info "read data surplus" {:reason ::read-data-surplus}))
    (let [[context type content] (recv-application-ciphertext context type content)]
      (condp = type
        tls13-st/content-type-application-data
        (update context :recv-bytes vec-conj content)
        tls13-st/content-type-alert
        (recv-application-alert context content)
        tls13-st/content-type-handshake
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
      (send-application-ciphertext tls13-st/content-type-application-data content)))

(defn send-close-notify
  "Send close notify."
  [context]
  (-> context
      check-writable
      (merge {:write-close? true})
      (send-application-ciphertext
       tls13-st/content-type-alert
       (st/pack tls13-st/st-alert
                {:level tls13-st/alert-level-warning
                 :description tls13-st/alert-description-close-notify}))))

(defn send-key-update
  "Send key update."
  [context]
  (-> context
      check-writable
      (send-application-ciphertext
       tls13-st/content-type-handshake
       (st/pack tls13-st/st-handshake
                {:msg-type tls13-st/handshake-type-key-update
                 :msg-data (st/pack tls13-st/st-handshake-key-update tls13-st/key-update-not-requested)}))
      (update :application-encryptor tls13-crypto/update-key)
      ;; reset key update flag
      (merge {:key-update? false})))

(defn send-key-update-request
  "Send key update request."
  [context]
  (-> context
      check-writable
      (send-application-ciphertext
       tls13-st/content-type-handshake
       (st/pack tls13-st/st-handshake
                {:msg-type tls13-st/handshake-type-key-update
                 :msg-data (st/pack tls13-st/st-handshake-key-update tls13-st/key-update-requested)}))))
