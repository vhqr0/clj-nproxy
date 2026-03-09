(ns clj-nproxy.config
  "Config IO utils."
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clj-nproxy.struct :as st]
            [clj-nproxy.crypto.keystore :as ks]))

(set! clojure.core/*warn-on-reflection* true)

(defn config-file
  "Get config file by name."
  [opts name]
  (let [{:keys [config-dir] :or {config-dir ".nproxy"}} opts]
    (io/as-file (str config-dir "/" name))))

(defn write
  "Write content to config file."
  [opts name content]
  (spit (config-file opts name) content))

(defn read-str
  "Read str config file."
  ^String [opts name]
  (slurp (config-file opts name)))

(defn read-bytes
  "Read bytes from config file."
  ^bytes [opts name]
  (with-open [is (io/input-stream (config-file opts name))]
    (st/read-all is)))

(defn read-key-store
  "Read key store from config file."
  [opts {:keys [name alias password]}]
  (let [ks (-> (read-bytes opts name) (ks/bytes->key-store password))
        alias (or alias (first (ks/key-store->aliases ks)))
        certs (ks/key-store->cert-chain ks alias)
        pri (ks/key-store->key ks alias password)]
    {:certs certs :pri pri}))

(defn read-trust-store
  "Read trust store from config file."
  [opts {:keys [name aliases password]}]
  (let [ks (-> (read-bytes opts name) (ks/bytes->key-store password))
        aliases (or aliases (ks/key-store->aliases ks))]
    (->> aliases (keep (partial ks/key-store->cert ks)) vec)))

(declare read-edn)

(defn opts->edn-readers
  "Convert opts to edn readers."
  [opts]
  {'file               (partial read-edn opts)
   'config/edn         (partial read-edn opts)
   'config/str         (partial read-str opts)
   'config/bytes       (partial read-bytes opts)
   'config/key-store   (partial read-key-store opts)
   'config/trust-store (partial read-trust-store opts)})

(defn read-edn
  "Read edn from config file."
  [opts name]
  (edn/read-string {:readers (opts->edn-readers opts)} (read-str opts name)))
