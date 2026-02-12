(ns clj-nproxy.tool.vsub
  (:refer-clojure :exclude [list])
  (:require [clojure.string :as str]
            [clojure.data.json :as json]
            [clj-nproxy.config :as config])
  (:import [java.util Base64]))

(set! clojure.core/*warn-on-reflection* true)

(defn base64-decode
  "Decode base64 string to string."
  ^String [^String s]
  (String. (.decode (Base64/getDecoder) s)))

(defn sub->nodes
  "Parse sub text, return seq of vmess nodes."
  [^String sub]
  (->> (str/split-lines (base64-decode sub))
       (keep
        (fn [url]
          (let [url (str/trim url)]
            (when (str/starts-with? url "vmess://")
              (-> (subs url 8) base64-decode json/read-str)))))))

(defn node->outbound-opts
  "Convert node to vmess outbound opts."
  [node]
  (let [{:strs [ps id add port net tls host path] :or {net "tcp" path "/"}} node
        port (parse-long port)
        ssl? (= tls "tls")]
    {:type :proxy
     :name ps
     :net-opts (case net
                 "tcp" {:type :tcp :host add :port port :ssl? ssl?}
                 "ws" (let [schema (if ssl? "wss" "ws")
                            uri (format "%s://%s:%d%s" schema add port path)]
                        (merge
                         {:type :ws :uri uri}
                         (when (some? host)
                           {:headers {"host" host}}))))
     :proxy-opts {:type :vmess :uuid id}}))

(defn read-nodes
  [opts]
  (let [sub (config/read-text opts "sub.txt")]
    (->> sub sub->nodes)))

(defn print-nodes
  [nodes]
  (doseq [[i node] (map-indexed vector nodes)]
    (prn {:index i :node node})))

(defn list
  [opts]
  (print-nodes (read-nodes opts)))

(defn fetch
  [opts]
  (let [url (str/trim (config/read-text opts "sub.url"))
        sub (str/trim (slurp url))]
    (config/write opts "sub.txt" sub)
    (list opts)))

(defn select
  [opts]
  (let [nodes (read-nodes opts)]
    (print-nodes nodes)
    (let [select (read)
          select (set (if (coll? select) select [select]))
          outbounds (vec (->> nodes
                              (keep-indexed
                               (fn [i node]
                                 (when (contains? select i)
                                   (node->outbound-opts node))))))
          outbound {:type :rand-dispatch :outbounds outbounds}]
      (config/write opts "sub.edn" outbound))))
