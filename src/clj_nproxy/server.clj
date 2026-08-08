(ns clj-nproxy.server
  "Proxy server."
  (:require [clojure.string :as str]
            [clj-nproxy.struct :as st]
            [clj-nproxy.net :as net])
  (:import [java.util.logging Logger Level]
           [java.io InputStream OutputStream]))

(set! clojure.core/*warn-on-reflection* true)

(defmulti mk-inbound
  "Make proxy inbound based on options, return closeable object.
  callback: accept {:keys [input-stream output-stream host port]}"
  (fn [opts _callback] (:type opts)))

(defmulti mk-outbound
  "Make proxy outbound based on options, block until callback finished.
  callback: accept {:keys [input-stream output-stream]}"
  (fn [opts _client _callback] (:type opts)))

(defmulti edn->inbound-opts :type)
(defmulti edn->outbound-opts :type)
(defmethod edn->inbound-opts :default [opts] opts)
(defmethod edn->outbound-opts :default [opts] opts)

;;; block

(defmethod mk-outbound :block [{:keys [block-ms] :or {block-ms 3000}} _client callback]
  (when (pos? block-ms)
    (Thread/sleep ^long block-ms))
  (callback
   {:input-stream (InputStream/nullInputStream)
    :output-stream (OutputStream/nullOutputStream)}))

;;; direct

(defmethod mk-outbound :direct [_opts {:keys [host port]} callback]
  (net/mk-net-client {:type :tcp :host host :port port} callback))

;;; redirect

(defmethod mk-inbound :redirect [{:keys [net-opts host port]} callback]
  (net/mk-net-server
   net-opts
   (fn [net-client]
     (callback (merge net-client {:host host :port port})))))

(defmethod edn->inbound-opts :redirect [opts]
  (update opts :net-opts net/edn->net-server-opts))

;;; proxy

(defmethod mk-inbound :proxy [{:keys [net-opts proxy-opts]} callback]
  (net/mk-net-server
   net-opts
   (fn [client]
     (net/mk-proxy-server client proxy-opts callback))))

(defmethod mk-outbound :proxy [{:keys [net-opts proxy-opts]} {:keys [host port]} callback]
  (net/mk-net-client
   net-opts
   (fn [server]
     (net/mk-proxy-client server proxy-opts host port callback))))

(defmethod edn->inbound-opts :proxy [opts]
  (-> opts
      (update :net-opts net/edn->net-server-opts)
      (update :proxy-opts net/edn->proxy-server-opts)))

(defmethod edn->outbound-opts :proxy [opts]
  (-> opts
      (update :net-opts net/edn->net-client-opts)
      (update :proxy-opts net/edn->proxy-client-opts)))

;;; multi

(defmethod mk-inbound :multi [{:keys [inbounds]} callback]
  (let [inbounds (->> inbounds (mapv #(mk-inbound % callback)))]
    (st/mk-closeable
     #(run! st/safe-close inbounds))))

(defmethod edn->inbound-opts :multi [opts]
  (update opts :inbounds (partial mapv edn->inbound-opts)))

;;; rand-dispatch

(defmethod mk-outbound :rand-dispatch [{:keys [outbounds]} client callback]
  (mk-outbound (rand-nth outbounds) client callback))

(defmethod edn->outbound-opts :rand-dispatch [opts]
  (update opts :outbounds (partial mapv edn->outbound-opts)))

;;; tag

(defn match-tag
  "Match host's tag in tags."
  [host tags]
  (when (not (str/blank? host))
    (if-let [tag (get tags host)]
      tag
      (when-let [host (second (str/split host #"\." 2))]
        (recur host tags)))))

(defmethod mk-inbound :tag [{:keys [inbound tags default-tag]} callback]
  (mk-inbound
   inbound
   (fn [{:keys [host] :as client}]
     (let [tag (or
                (when (some? tags)
                  (match-tag host tags))
                default-tag)]
       (callback (assoc client :tag tag))))))

(defmethod edn->inbound-opts :tag [opts]
  (update opts :inbound edn->inbound-opts))

;;; tag-dispatch

(defmethod mk-outbound :tag-dispatch [{:keys [outbounds]} {:keys [tag] :as client} callback]
  (mk-outbound (get outbounds tag) client callback))

(defmethod edn->outbound-opts :tag-dispatch [opts]
  (update opts :outbounds update-vals edn->outbound-opts))

;;; log

(def logger (delay (Logger/getLogger "nproxy")))

(def log-keys [:host :port :tag])

(defn ->log
  [opts client]
  (select-keys client (get opts :log-keys log-keys)))

(defmethod mk-inbound :log [{:keys [inbound] :as opts} callback]
  (mk-inbound
   inbound
   (fn [client]
     (let [log (->log opts client)]
       (.log ^Logger (force logger) Level/INFO (str log)))
     (callback client))))

(defmethod edn->inbound-opts :log [opts]
  (update opts :inbound edn->inbound-opts))

;;; catch

(defmulti catch-error
  (fn [opts _client _error] (:catch-type opts)))

(defmethod catch-error :ignore [_opts _client _error])

(defmethod catch-error :throw [_opts _client error]
  (throw error))

(defmethod catch-error :log [opts client error]
  (let [log (-> (->log opts client) (assoc :error (str error)))]
    (.log ^Logger (force logger) Level/FINE (str log) ^Throwable error)))

(defmethod mk-inbound :catch [{:keys [inbound] :as opts} callback]
  (mk-inbound
   inbound
   (fn [client]
     (try
       (callback client)
       (catch Exception error
         (catch-error opts client error))))))

(defmethod mk-outbound :catch [{:keys [outbound] :as opts} client callback]
  (mk-outbound
   outbound client
   (fn [server]
     (try
       (callback server)
       (catch Exception error
         (catch-error opts client error))))))

(defmethod edn->inbound-opts :catch [opts]
  (update opts :inbound edn->inbound-opts))

(defmethod edn->outbound-opts :catch [opts]
  (update opts :outbound edn->outbound-opts))

;;; thread

(defmethod edn->inbound-opts :thread [{:keys [inbounds]}]
  (->> (rest inbounds)
       (reduce #(assoc %2 :inbound %1) (first inbounds))
       edn->inbound-opts))

(defmethod edn->outbound-opts :thread [{:keys [outbounds]}]
  (->> (rest outbounds)
       (reduce #(assoc %2 :outbound %1) (first outbounds))
       edn->outbound-opts))

;;; server

(defn start-server
  "Start proxy server."
  [opts]
  (let [{:keys [inbound outbound]} opts]
    (mk-inbound
     inbound
     (fn [client]
       (mk-outbound
        outbound client
        (fn [server]
          (st/pipe client server)))))))

(defn edn->server-opts
  [opts]
  (-> opts
      (update :inbound edn->inbound-opts)
      (update :outbound edn->outbound-opts)))
