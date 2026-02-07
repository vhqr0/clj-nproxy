(ns clj-nproxy.server
  (:require [clojure.string :as str]
            [clj-nproxy.struct :as st]
            [clj-nproxy.net :as net]
            [clj-nproxy.proxy :as proxy])
  (:import [java.util.concurrent StructuredTaskScope StructuredTaskScope$Joiner]))

(defmulti mk-inbound
  "Make proxy inbound based on options, return closeable object.
  callback: accept {:keys [input-stream output-stream host port]}"
  (fn [opts _callback] (:type opts)))

(defmulti mk-outbound
  "Make proxy outbound based on options, block until callback finished.
  callback: accept {:keys [input-stream output-stream]}"
  (fn [opts _host _port _callback] (:type opts)))

(defmethod mk-outbound :block [_opts _host _port callback]
  (net/mk-client {:type :null} callback))

(defmethod mk-outbound :direct [_opts host port callback]
  (net/mk-client {:type :tcp :host host :port port} callback))

(defmethod mk-inbound :proxy [{:keys [net-opts proxy-opts]} callback]
  (net/mk-server
   net-opts
   (fn [net-client]
     (proxy/mk-server
      proxy-opts
      (:input-stream net-client)
      (:output-stream net-client)
      (fn [proxy-client]
        (callback
         (merge
          {:peer (merge (:peer net-client) (:peer proxy-client))}
          (select-keys proxy-client [:input-stream :output-stream :host :port]))))))))

(defmethod mk-outbound :proxy [{:keys [net-opts proxy-opts]} host port callback]
  (net/mk-client
   net-opts
   (fn [net-server]
     (proxy/mk-client
      proxy-opts
      (:input-stream net-server)
      (:output-stream net-server)
      host
      port
      (fn [proxy-server]
        (callback
         (merge
          {:peer (merge (:peer net-server) (:peer proxy-server))}
          (select-keys proxy-server [:input-stream :output-stream]))))))))

(defmethod mk-inbound :multi [{:keys [inbounds]} callback]
  (let [inbounds (->> inbounds (mapv #(mk-inbound % callback)))]
    (st/mk-closeable
     (fn []
       (doseq [inbound inbounds]
         (st/safe-close inbound))))))

(defmethod mk-outbound :rand-dispatch [{:keys [outbounds]} host port callback]
  (let [opts (rand-nth outbounds)]
    (mk-outbound opts host port callback)))

(defn match-tag
  "Match host's tag in tags."
  [host tags]
  (when (not (str/blank? host))
    (if-let [tag (get tags host)]
      tag
      (when-let [host (second (str/split host #"\." 2))]
        (recur host tags)))))

^:rct/test
(comment
  (match-tag "google.com" {"google.com" :proxy}) ; => :proxy
  (match-tag "www.google.com" {"google.com" :proxy}) ; => :proxy
  (match-tag "www.a.google.com" {"google.com" :proxy}) ; => :proxy
  (match-tag "ads.google.com" {"google.com" :proxy "ads.google.com" :block}) ; => :block
  (match-tag "baidu.com" {"google.com" :proxy}) ; => nil
  )

(defmethod mk-outbound :tag-dispatch [{:keys [outbounds tags default-tag]} host port callback]
  (let [tag (or (match-tag host tags) default-tag)
        outbound (get outbounds tag)]
    (mk-outbound
     outbound host port
     (fn [server]
       (update server :peer merge {:tag tag})))))

;;; server

(defn pipe
  "Pipe between client and server."
  [client server]
  (let [joiner (StructuredTaskScope$Joiner/allSuccessfulOrThrow)]
    (with-open [scope (StructuredTaskScope/open joiner)]
      (let [f1 (.fork scope ^Runnable #(st/copy (:input-stream client) (:output-stream server)))
            f2 (.fork scope ^Runnable #(st/copy (:input-stream server) (:output-stream client)))]
        (.join scope)))))

(def default-server-opts
  {:inbound {:type :proxy
             :net-opts {:type :tcp :port 1080}
             :proxy-opts {:type :socks5}}
   :outbound {:type :direct}
   :log-fn prn})

(defn start-server
  "Start proxy server."
  [opts]
  (let [{:keys [inbound outbound log-fn]} (merge default-server-opts opts)]
    (mk-inbound
     inbound
     (fn [{:keys [host port] cinfo :peer :as client}]
       (mk-outbound
        outbound host port
        (fn [{sinfo :peer :as server}]
          (log-fn {:level :info :event :pipe :client cinfo :server sinfo})
          (try
            (pipe client server)
            (catch Exception _))))))))

(comment
  (start-server {}))
