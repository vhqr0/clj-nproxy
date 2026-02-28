(ns clj-nproxy.server
  "Proxy server."
  (:require [clojure.string :as str]
            [clj-nproxy.struct :as st]
            [clj-nproxy.net :as net]
            [clj-nproxy.proxy :as proxy]))

(set! clojure.core/*warn-on-reflection* true)

(defmulti mk-inbound
  "Make proxy inbound based on options, return closeable object.
  callback: accept {:keys [input-stream output-stream host port]}"
  (fn [opts _callback] (:type opts)))

(defmulti mk-outbound
  "Make proxy outbound based on options, block until callback finished.
  callback: accept {:keys [input-stream output-stream]}"
  (fn [opts _host _port _callback] (:type opts)))

(defmulti edn->inbound-opts :type)
(defmulti edn->outbound-opts :type)
(defmethod edn->inbound-opts :default [opts] opts)
(defmethod edn->outbound-opts :default [opts] opts)

(defmethod mk-outbound :block [{:keys [block-ms] :or {block-ms 3000}} _host _port callback]
  (when (pos? block-ms)
    (Thread/sleep ^long block-ms))
  (net/mk-client {:type :null} callback))

(defmethod mk-outbound :direct [_opts host port callback]
  (net/mk-client {:type :tcp :host host :port port} callback))

(defmethod mk-inbound :proxy [{:keys [name net-opts proxy-opts]} callback]
  (net/mk-server
   net-opts
   (fn [net-client]
     (proxy/mk-server
      proxy-opts net-client
      (fn [proxy-client]
        (callback
         (merge
          {:peer (merge (when (some? name) {:name name}) (:peer net-client) (:peer proxy-client))}
          (select-keys proxy-client [:input-stream :output-stream :host :port]))))))))

(defmethod mk-outbound :proxy [{:keys [name net-opts proxy-opts]} host port callback]
  (net/mk-client
   net-opts
   (fn [net-server]
     (proxy/mk-client
      proxy-opts net-server host port
      (fn [proxy-server]
        (callback
         (merge
          {:peer (merge (when (some? name) {:name name}) (:peer net-server) (:peer proxy-server))}
          (select-keys proxy-server [:input-stream :output-stream]))))))))

(defmethod edn->inbound-opts :proxy [opts]
  (-> opts
      (update :net-opts net/edn->server-opts)
      (update :proxy-opts proxy/edn->server-opts)))

(defmethod edn->outbound-opts :proxy [opts]
  (-> opts
      (update :net-opts net/edn->client-opts)
      (update :proxy-opts proxy/edn->client-opts)))

(defmethod mk-inbound :multi [{:keys [inbounds]} callback]
  (let [inbounds (->> inbounds (mapv #(mk-inbound % callback)))]
    (st/mk-closeable
     (fn []
       (doseq [inbound inbounds]
         (st/safe-close inbound))))))

(defmethod edn->inbound-opts :multi [opts]
  (update opts :inbounds (partial mapv edn->inbound-opts)))

(defmethod mk-outbound :rand-dispatch [{:keys [outbounds]} host port callback]
  (let [opts (rand-nth outbounds)]
    (mk-outbound opts host port callback)))

(defmethod edn->outbound-opts :rand-dispatch [opts]
  (update opts :outbounds (partial mapv edn->outbound-opts)))

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
       (callback (update server :peer merge {:tag tag}))))))

(defmethod edn->outbound-opts :tag-dispatch [opts]
  (update opts :outbounds update-vals edn->outbound-opts))

;;; server

(defn ->log
  "Construct log data."
  [level event data]
  (merge {:timestamp (System/currentTimeMillis) :level level :event event} data))

(defn ->info-log
  "Construct info log."
  [event data]
  (->log :info event data))

(defn ->error-log
  "Construct error log."
  [event error pr-error? data]
  (->log :error event
         (merge data
                {:error-str (str error)}
                (when pr-error?
                  {:error-pr-str (pr-str error)}))))

(defn start-server
  "Start proxy server."
  [opts]
  (let [{:keys [inbound outbound log-fn pr-error?]
         :or {log-fn prn pr-error? false}}
        opts]
    (mk-inbound
     inbound
     (fn [{:keys [host port] cinfo :peer :as client}]
       (let [req {:id (str (random-uuid)) :host host :port port}]
         (log-fn (->info-log :connect {:req req :client cinfo}))
         (try
           (mk-outbound
            outbound host port
            (fn [{sinfo :peer :as server}]
              (log-fn (->info-log :pipe {:req req :client cinfo :server sinfo}))
              (try
                (st/pipe client server)
                (catch Exception error
                  (log-fn (->error-log :pipe-error error pr-error? {:req req :client cinfo :server sinfo}))))))
           (catch Exception error
             (log-fn (->error-log :connect-error error pr-error? {:req req :client cinfo})))))))
    (log-fn (->info-log :start {}))))

(defn edn->server-opts
  [opts]
  (-> opts
      (update :inbound edn->inbound-opts)
      (update :outbound edn->outbound-opts)))
