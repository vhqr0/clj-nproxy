(ns clj-nproxy.tool.core
  (:require [clojure.edn :as edn])
  (:import [java.io File]))

(set! clojure.core/*warn-on-reflection* true)

(defn config-file
  [opts name]
  (let [{:keys [config-dir] :or {config-dir ".nproxy"}} opts]
    (File. (str config-dir "/" name))))

(defn read-text
  [opts name]
  (slurp (config-file opts name)))

(defn read-edn
  [opts name]
  (edn/read-string
   {:readers {'file #(read-edn opts %)}}
   (read-text opts name)))

(defn write-content
  [opts name content]
  (spit (config-file opts name) content))
