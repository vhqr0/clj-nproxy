(ns clj-nproxy.config
  "Config IO utils."
  (:refer-clojure :exclude [write])
  (:require [clojure.edn :as edn])
  (:import [java.io File]))

(set! clojure.core/*warn-on-reflection* true)

(defn config-file
  "Get config file by name."
  [opts name]
  (let [{:keys [config-dir] :or {config-dir ".nproxy"}} opts]
    (File. (str config-dir "/" name))))

(defn read-text
  "Read text from config file."
  [opts name]
  (slurp (config-file opts name)))

(defn read-edn
  "Read edn from config file."
  [opts name]
  (edn/read-string
   {:readers {'file #(read-edn opts %)}}
   (read-text opts name)))

(defn write
  "Write content to config file."
  [opts name content]
  (spit (config-file opts name) content))
