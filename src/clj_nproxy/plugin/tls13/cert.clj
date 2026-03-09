(ns clj-nproxy.plugin.tls13.cert
  "TLS 1.3 cert utils."
  (:require [clj-nproxy.plugin.tls13.struct :as tls13-st])
  (:import [java.security PublicKey]
           [java.security.cert X509Certificate]))

(def algo->scheme
  {"Ed25519"         tls13-st/signature-scheme-ed25519
   "Ed448"           tls13-st/signature-scheme-ed448
   "SHA256withECDSA" tls13-st/signature-scheme-ecdsa-secp256r1-sha256
   "SHA384withECDSA" tls13-st/signature-scheme-ecdsa-secp384r1-sha384
   "SHA512withECDSA" tls13-st/signature-scheme-ecdsa-secp521r1-sha512
   "SHA256withRSA"   tls13-st/signature-scheme-rsa-pss-rsae-sha256
   "SHA384withRSA"   tls13-st/signature-scheme-rsa-pss-rsae-sha384
   "SHA512withRSA"   tls13-st/signature-scheme-rsa-pss-rsae-sha512
   "RSASSA-PSS"      tls13-st/signature-scheme-rsa-pss-rsae-sha256})

(defn cert->scheme
  "Get certificate signature scheme."
  ^long [^X509Certificate cert]
  (let [algo (.getSigAlgName cert)]
    (or (get algo->scheme algo)
        (throw (ex-info "invalid certificate algorithm" {:reason ::invalid-certificate-algorithm :certificate-algorithm algo})))))

(defn cert->pub
  "Get certificate public key."
  ^PublicKey [^X509Certificate cert]
  (.getPublicKey cert))

(defn valid-cert-chain?
  "Simple cert chain validation."
  ^Boolean [certs]
  (->> certs
       (partition 2 1)
       (every?
        (fn [^X509Certificate child ^X509Certificate parent]
          (.verify child (.getPublicKey parent))))))
