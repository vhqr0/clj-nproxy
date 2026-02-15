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

(defn node->ssl-params
  "Convert node to ssl params."
  [{:strs [add host sni alpn]}]
  (merge
   (let [sni (or sni host add)]
     {:sni [sni]})
   (when (some? alpn)
     {:alpn [alpn]})))

(defn node->base-net-opts
  "Convert node to base net opts."
  [{:strs [add port tls] :as node}]
  (merge
   {:host add :port (parse-long port)}
   (when (= tls "tls")
     {:ssl? true :ssl-params (node->ssl-params node)})))

^:rct/test
(comment
  (node->base-net-opts {"add" "foo", "port" "80", "tls" ""}) ; => {:host "foo" :port 80}
  (node->base-net-opts {"add" "foo", "port" "80", "tls" "tls"}) ; => {:host "foo" :port 80 :ssl? true :ssl-params {:sni ["foo"]}}
  (node->base-net-opts {"add" "foo", "port" "80", "tls" "tls", "host" "bar"}) ; => {:host "foo" :port 80 :ssl? true :ssl-params {:sni ["bar"]}}
  (node->base-net-opts {"add" "foo", "port" "80", "tls" "tls", "alpn" "h2"}) ; => {:host "foo" :port 80 :ssl? true :ssl-params {:sni ["foo"] :alpn ["h2"]}}
  )

(defmethod node->net-opts "tcp" [node]
  (merge {:type :tcp}
         (node->base-net-opts node)))

(defmethod node->net-opts "ws" [{:strs [add path host] :or {path "/"} :as node}]
  (merge {:type :ws}
         (node->base-net-opts node)
         {:path path :headers {"host" (or host add)}}))

^:rct/test
(comment
  (node->net-opts {"net" "ws", "add" "foo", "port" "80", "tls" "tls", "host" "bar"})
  ;; => {:type :ws :host "foo" :port 80 :ssl? true :ssl-params {:sni ["bar"]} :path "/" :headers {"host" "bar"}}
  )

(defn node->proxy-opts
  "Convert node to vmess proxy opts."
  [{:strs [id]}]
  {:type :vmess :uuid id})

(defn node->outbound-opts
  "Convert node to vmess outbound opts."
  [{:strs [ps] :as node}]
  {:type :proxy
   :name ps
   :net-opts (node->net-opts node)
   :proxy-opts (node->proxy-opts node)})

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
  "Fetch sub then read and print nodes."
  [opts]
  (let [url (str/trim (config/read-text opts "sub.url"))
        sub (str/trim (slurp url))]
    (config/write opts "sub.txt" sub)
    (list opts)))

(defn gen
  "Read and print nodes then select some nodes and generate outobund config."
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
