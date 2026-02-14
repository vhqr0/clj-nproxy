(ns clj-nproxy.tool.vsub
  "Fetch and generate outbound config via V2rayN subscribe protocol:
  https://github.com/2dust/v2rayN/wiki/Description-of-VMess-share-link"
  (:refer-clojure :exclude [list])
  (:require [clojure.string :as str]
            [clojure.data.json :as json]
            [clj-nproxy.bytes :as b]
            [clj-nproxy.config :as config]))

(set! clojure.core/*warn-on-reflection* true)

(defn sub->urls
  "Parse sub text, return urls."
  [^String sub]
  (let [lines (-> sub b/base64->bytes b/bytes->str str/split-lines)]
    (->> lines (map str/trim) (remove str/blank?))))

(defn url->node
  "Convert url to vmess node, or nil if not a vmess url."
  [^String url]
  (when (str/starts-with? url "vmess://")
    (-> (subs url 8) b/base64->bytes b/bytes->str json/read-str)))

(defn sub->nodes
  "Parse sub text, return vmess nodes."
  [^String sub]
  (->> sub sub->urls (keep url->node)))

(defmulti node->net-opts
  "Convert node to net opts."
  (fn [node] (get node "net" "tcp")))

(defn ssl?
  "Check if node use ssl."
  [{:keys [tls] :or {tls ""}}]
  (case tls "" false "tls" true))

(defmethod node->net-opts "tcp" [{:strs [add port] :as node}]
  {:type :tcp :host add :port (parse-long port) :ssl? (ssl? node)})

(defmethod node->net-opts "ws" [{:strs [add port path host] :or {path "/"} :as node}]
  {:type :ws :host add :port (parse-long port) :ssl? (ssl? node)
   :path path :headers {"host" (or host add)}})

(defn node->outbound-opts
  "Convert node to vmess outbound opts."
  [node]
  (let [{:strs [ps id]} node]
    {:type :proxy
     :name ps
     :net-opts (node->net-opts node)
     :proxy-opts {:type :vmess :uuid id}}))

(defn read-nodes
  "Read nodes."
  [opts]
  (let [sub (config/read-text opts "sub.txt")]
    (->> sub sub->nodes)))

(defn print-nodes
  "Print nodes."
  [nodes]
  (doseq [[i node] (map-indexed vector nodes)]
    (prn {:index i :node node})))

(defn list
  "Read and print nodes."
  [opts]
  (print-nodes (read-nodes opts)))

(defn fetch
  "Fetch sub, then read and print nodes."
  [opts]
  (let [url (str/trim (config/read-text opts "sub.url"))
        sub (str/trim (slurp url))]
    (config/write opts "sub.txt" sub)
    (list opts)))

(defn gen
  "Read and print nodes, then select some nodes and generate outobund config."
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
