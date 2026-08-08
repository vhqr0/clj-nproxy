(ns clj-nproxy.tool.dlc
  "Generate tags config from domain-list-community:
  - origin: https://github.com/v2fly/domain-list-community
  - fork: https://github.com/vhqr0/domain-list-community"
  (:require [clojure.string :as str]
            [clojure.java.io :as io]
            [clj-nproxy.config :as config]))

(set! clojure.core/*warn-on-reflection* true)

(defn data-file
  "Get data file by name."
  [opts name]
  (let [{:keys [data-dir] :or {data-dir ".nproxy/domain-list-community/data"}} opts]
    (io/as-file (str data-dir "/" name))))

(defn trim-comments
  "Trim comments."
  [line]
  (if-let [i (str/index-of line \#)]
    (subs line 0 i)
    line))

(def line-re
  #"^((\w+):)?([^\s\t#]+)( @([^\s\t#]+))?$")

(defn read-data
  "Read data."
  [opts name]
  (->> (data-file opts name)
       slurp
       str/split-lines
       (map (comp str/trim trim-comments))
       (remove str/blank?)
       (map
        (fn [line]
          (if-let [matches (re-matches line-re line)]
            (let [command (or (get matches 2) "domain")
                  name (get matches 3)
                  tag (get matches 5)]
              [command name tag])
            (throw (ex-info "invalid line" {:reason ::invalid-line :line line})))))))

(defmulti read-domains
  "Read domains."
  (fn [_opts command _name _tag] command))

(defmethod read-domains :default [_opts command name tag]
  (throw (ex-info "invalid command" {:reason ::invalid-command :command command :name name :tag tag})))

;; NOTE: skip regexp rules
(defmethod read-domains "regexp" [_opts _command _name _tag])

(defmethod read-domains "domain" [_opts _command name tag] [[name tag]])
(defmethod read-domains "full" [_opts _command name tag] [[name tag]])

(defn filter-domains-by-tag
  "Filter domains by tag.
  - If tag is nil, no filter.
  - If tag starts with '-', remove by tag (rest chars).
  - If tag not starts with '-', filter by tag."
  [tag domains]
  (if (nil? tag)
    domains
    (if-not (= \- (first tag))
      (->> domains (filter #(= tag (second %))))
      (let [tag (subs tag 1)]
        (->> domains (remove #(= tag (second %))))))))

(defmethod read-domains "include" [opts _command name tag]
  (->> (read-data opts name)
       (mapcat
        (fn [[command name tag]]
          (read-domains opts command name tag)))
       (filter-domains-by-tag tag)))

(defn read-domains-with-default-tag
  "Read domains, add default tag."
  ([opts name default-tag]
   (read-domains-with-default-tag opts "include" name nil default-tag))
  ([opts command name tag default-tag]
   (->> (read-domains opts command name tag)
        (map
         (fn [[domain tag]]
           [domain (or tag default-tag)])))))

(def tag-map
  "Mapping from dlc tags to nproxy tags."
  {"ads" :block "cn" :direct "!cn" :proxy})

(defn gen
  "Read tags from data, then generate tags config."
  [opts]
  (let [tags (->> (concat
                   (read-domains-with-default-tag opts "cn" "cn")
                   (read-domains-with-default-tag opts "tld-!cn" "!cn")
                   (read-domains-with-default-tag opts "geolocation-!cn" "!cn")
                   (read-domains-with-default-tag opts "category-ads-all" "ads"))
                  (map
                   (fn [[domain tag]]
                     (if-let [tag (get tag-map tag)]
                       [domain tag]
                       (throw (ex-info "invalid tag" {:reason ::invalid-tag :domain domain :tag tag})))))
                  (into {}))]
    (config/write opts "tags.edn" tags)))
