(ns clj-nproxy.tool.dlc
  (:require [clojure.string :as str]
            [clj-nproxy.config :as config])
  (:import [java.io File]))

(set! clojure.core/*warn-on-reflection* true)

(defn data-file
  "Get data file by name."
  [opts name]
  (let [{:keys [data-dir] :or {data-dir "domain-list-community/data"}} opts]
    (File. (str data-dir "/" name))))

(defn trim-comments
  "Trim comments."
  [line]
  (if-let [i (str/index-of line \#)]
    (subs line 0 i)
    line))

^:rct/test
(comment
  (trim-comments "foo # bar") ; => "foo "
  (trim-comments "foo bar") ; => "foo bar"
  )

(def line-re
  #"^((\w+):)?([^\s\t#]+)( @([^\s\t#]+))?")

^:rct/test
(comment
  (re-matches line-re "a.baidu.com") ; => ["a.baidu.com" nil nil "a.baidu.com" nil nil]
  (re-matches line-re "a.baidu.com @ads") ; => ["a.baidu.com @ads" nil nil "a.baidu.com" " @ads" "ads"]
  (re-matches line-re "include:geolocation-cn") ; => ["include:geolocation-cn" "include:" "include" "geolocation-cn" nil nil]
  )

(def tag-map
  "Mapping from dlc tags to nproxy tags."
  {"ads" :block "cn" :direct "!cn" :proxy})

(defn read-data-tags
  "Read tags from data file."
  [opts name default-tag]
  (->> (slurp (data-file opts name))
       str/split-lines
       (map (comp str/trim trim-comments))
       (remove str/blank?)
       (mapcat
        (fn [line]
          (if-let [matches (re-matches line-re line)]
            (case (or (get matches 2) "domain")
              ("domain" "full")
              (let [domain (get matches 3)
                    tag (or (get matches 5) default-tag)]
                (if-let [tag (get tag-map tag)]
                  [[domain tag]]
                  (throw (ex-info "unknown tag" {:reason ::unknown-tag :line line}))))
              "include"
              (let [name (get matches 3)]
                (read-data-tags opts name default-tag))
              ;; NOTE not supported
              "regexp" nil
              (throw (ex-info "unknown command" {:reason ::unknown-command :line line})))
            (throw (ex-info "mismatch" {:reason ::mismatch :line line})))))))

(defn gen
  "Read tags from data, then generate tags config."
  [opts]
  (let [tags (into {} (concat
                       (read-data-tags opts "cn" "cn")
                       (read-data-tags opts "geolocation-!cn" "!cn")))]
    (config/write opts "tags.edn" tags)))
