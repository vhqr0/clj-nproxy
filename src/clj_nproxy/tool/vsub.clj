(ns clj-nproxy.tool.vsub
  "Fetch and generate outbound config via V2rayN subscribe protocol:
  https://github.com/2dust/v2rayN/wiki/Description-of-VMess-share-link"
  (:refer-clojure :exclude [list])
  (:require [clojure.string :as str]
            [clojure.data.json :as json]
            [clj-nproxy.bytes :as b]
            [clj-nproxy.struct :as st]
            [clj-nproxy.http :as http]
            [clj-nproxy.server :as server]
            [clj-nproxy.config :as config]
            clj-nproxy.cli)
  (:import [java.time Duration]
           [java.util.concurrent StructuredTaskScope
            StructuredTaskScope$Joiner StructuredTaskScope$Configuration StructuredTaskScope$TimeoutException]))

(set! clojure.core/*warn-on-reflection* true)

(comment
  (System/setProperty "jdk.httpclient.allowRestrictedHeaders" "host"))

;;; parse

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

(defmethod node->net-opts "tcp" [{:strs [add port tls] :as node}]
  (merge
   {:type :tcp :host add :port (parse-long port)}
   (when (= tls "tls")
     {:ssl? true :ssl-params (node->ssl-params node)})))

(defmethod node->net-opts "ws" [{:strs [add port path host tls] :or {path "/"}}]
  (let [scheme (if (= tls "tls") "wss" "ws")]
    {:type :ws
     :uri (format "%s://%s:%s%s" scheme add port path)
     :headers {"host" (or host add)}}))

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

(defn nodes->outbound-opts
  "Convert nodes to outbound opts."
  [nodes]
  (if (= 1 (count nodes))
    (-> nodes first node->outbound-opts)
    {:type :rand-dispatch :outbounds (mapv node->outbound-opts nodes)}))

;;; helpers

(defn read-url
  "Read url."
  [opts]
  (str/trim (config/read-str opts "sub.url")))

(defn read-nodes
  "Read nodes."
  [opts]
  (let [sub (config/read-str opts "sub.txt")]
    (->> sub
         sub->urls
         (keep url->node)
         (map-indexed #(assoc %2 :index %1)))))

(defn print-nodes
  "Print nodes."
  [nodes]
  (->> nodes (map (juxt :index identity)) (run! prn)))

(defn select-nodes
  "Select nodes."
  [opts nodes]
  (let [select (or (:select opts) (read))]
    (if (= select :all)
      nodes
      (let [select (set (if (coll? select) select [select]))]
        (->> nodes (filter #(contains? select (:index %))))))))

(defn read-print-select-nodes
  "Read, print then select nodes."
  [opts]
  (let [nodes (read-nodes opts)]
    (print-nodes nodes)
    (select-nodes opts nodes)))

(defn ping-node
  "Ping node."
  [opts node]
  (let [{:keys [ping-method ping-host ping-port ping-path ping-headers]
         :or {ping-method "GET" ping-host "www.google.com" ping-port 80 ping-path "/"}}
        opts
        ping-hostport (http/pack-hostport ping-host ping-port)
        outbound (-> node node->outbound-opts server/edn->outbound-opts)]
    (server/mk-outbound
     outbound {:host ping-host :port ping-port}
     (fn [{is :input-stream os :output-stream}]
       (let [req {:method ping-method
                  :path ping-path
                  :headers (merge {"host" ping-hostport} ping-headers)}]
         (st/write-struct http/st-http-req os req)
         (st/flush os)
         (st/read-struct http/st-http-resp is))))))

(defn ping-result
  "Ping node, return result."
  [opts node]
  (try
    (let [start-time (System/currentTimeMillis)
          {:keys [status reason]} (ping-node opts node)
          end-time (System/currentTimeMillis)
          time (- end-time start-time)]
      {:result :ok :time time :status status :reason reason :node node})
    (catch Exception e
      {:result :error :error e :node node})))

(defn ping-results
  "Ping nodes, return results."
  [opts nodes]
  (let [{:keys [ping-timeout] :or {ping-timeout 3000}} opts
        aresults (atom [])]
    (with-open [scope (StructuredTaskScope/open
                       (StructuredTaskScope$Joiner/allSuccessfulOrThrow)
                       (fn [^StructuredTaskScope$Configuration config]
                         (.withTimeout config (Duration/ofMillis ping-timeout))))]
      (->> nodes
           (run!
            (fn [node]
              (.fork scope ^Runnable #(swap! aresults conj (ping-result opts node))))))
      (try
        (.join scope)
        (catch StructuredTaskScope$TimeoutException _)))
    @aresults))

;;; api

(defn list
  "Read and print nodes."
  [opts]
  (print-nodes (read-nodes opts)))

(defn fetch
  "Fetch sub then read and print nodes."
  [opts]
  (let [sub (-> opts read-url slurp str/trim)]
    (config/write opts "sub.txt" sub)
    (list opts)))

(defn gen
  "Read and print nodes then select some nodes and generate outobund config."
  [opts]
  (let [nodes (read-print-select-nodes opts)
        outbound (nodes->outbound-opts nodes)]
    (config/write opts "sub.edn" outbound)))

(defn ping
  "Read and print nodes then select some nodes and ping them."
  [opts]
  (let [nodes (read-print-select-nodes opts)]
    (->> (ping-results opts nodes)
         (run!
          (fn [result]
            (case (:result result)
              :ok (-> result prn)
              :error (-> result (update :error str) prn)))))))
