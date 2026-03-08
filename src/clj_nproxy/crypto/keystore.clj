(ns clj-nproxy.crypto.keystore
  (:import [java.io InputStream ByteArrayInputStream]
           [java.security PrivateKey PublicKey KeyFactory]
           [java.security.spec PKCS8EncodedKeySpec X509EncodedKeySpec]
           [java.security.cert Certificate CertificateFactory]))

(set! clojure.core/*warn-on-reflection* true)

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
   (with-open [is (ByteArrayInputStream. b)]
     (let [cert (read-cert type is)]
       (if (zero? (.available is))
         cert
         (throw (ex-info "certificate surplus" {:reason ::certificate-surplus})))))))
