(ns clj-nproxy.crypto.keystore
  "Common key store format."
  (:import [java.util Iterator Enumeration]
           [java.io InputStream ByteArrayInputStream]
           [java.security Key PrivateKey PublicKey KeyFactory KeyStore]
           [java.security.spec PKCS8EncodedKeySpec X509EncodedKeySpec]
           [java.security.cert Certificate CertificateFactory]))

(set! clojure.core/*warn-on-reflection* true)

(defn iter->seq
  "Convert iterator to sequence."
  [^Iterator iter]
  (when (.hasNext iter)
    (lazy-seq
     (cons (.next iter) (iter->seq iter)))))

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

;;; der

(defn pri->bytes
  "Convert private key to bytes."
  ^bytes [^PrivateKey pri]
  (.getEncoded pri))

(defn pub->bytes
  "Convert public key to bytes."
  ^bytes [^PublicKey pub]
  (.getEncoded pub))

(defn cert->bytes
  "Convert certificate to bytes."
  ^bytes [^Certificate cert]
  (.getEncoded cert))

(defn bytes->pri
  "Convert bytes to private key."
  ^PrivateKey [^String algo ^bytes b]
  (-> (KeyFactory/getInstance algo)
      (.generatePrivate (PKCS8EncodedKeySpec. b))))

(defn bytes->pub
  "Convert bytes to public key."
  ^PublicKey [^String algo ^bytes b]
  (-> (KeyFactory/getInstance algo)
      (.generatePublic (X509EncodedKeySpec. b))))

;; type: X509 GPG

(defn read-cert
  "Read certificate from stream."
  (^Certificate [^InputStream is]
   (read-cert "X509" is))
  (^Certificate [^String type ^InputStream is]
   (-> (CertificateFactory/getInstance type)
       (.generateCertificate is))))

(defn bytes->cert
  "Convert bytes to certificate."
  (^Certificate [^bytes b]
   (bytes->cert "X509" b))
  (^Certificate [^String type ^bytes b]
   (let [is (ByteArrayInputStream. b)
         cert (read-cert type is)]
     (if (zero? (.available is))
       cert
       (throw (ex-info "certificate surplus" {:reason ::certificate-surplus}))))))

;;; key store

;; type: PKCS12 JKS

(defn read-key-store
  "Read key store."
  (^KeyStore [^InputStream is ^String password]
   (read-key-store "PKCS12" is password))
  (^KeyStore [^String type ^InputStream is ^String password]
   (doto (KeyStore/getInstance type)
     (.load is (some-> password .toCharArray)))))

(defn bytes->key-store
  "Convert bytes to key store."
  (^KeyStore [^bytes b ^String password]
   (bytes->key-store "PKCS12" b password))
  (^KeyStore [^String type ^bytes b ^String password]
   (let [is (ByteArrayInputStream. b)
         key-store (read-key-store type is password)]
     (if (zero? (.available is))
       key-store
       (throw (ex-info "key store surplus" {:reason ::key-store-surplus}))))))

(defn key-store->aliases
  "Get key store aliases."
  [^KeyStore ks]
  (let [^Enumeration aliases (.aliases ks)]
    (iter->seq (.asIterator aliases))))

(defn key-store->cert
  "Get certificate from key store."
  ^Certificate [^KeyStore ks ^String alias]
  (.getCertificate ks alias))

(defn key-store->cert-chain
  "Get certificate chain from key store."
  [^KeyStore ks ^String alias]
  (.getCertificateChain ks alias))

(defn key-store->key
  "Get key from key store."
  ^Key [^KeyStore ks ^String alias ^String password]
  (.getKey ks alias (some-> password .toCharArray)))
