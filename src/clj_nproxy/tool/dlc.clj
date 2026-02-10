(ns clj-nproxy.tool.dlc
  (:require [clojure.string :as str]
            [clj-nproxy.tool.core :as core])
  (:import [java.io File]))

(set! clojure.core/*warn-on-reflection* true)

(defn data-file
  [opts name]
  (let [{:keys [data-dir] :or {data-dir "domain-list-community/data"}} opts]
    (File. (str data-dir "/" name))))

(def line-re
  #"^((\w+):)?([^\s\t#]+)( @([^\s\t#]+))?")

^:rct/test
(comment
  (re-matches line-re "a.baidu.com") ; => ["a.baidu.com" nil nil "a.baidu.com" nil nil]
  (re-matches line-re "a.baidu.com @ads") ; => ["a.baidu.com @ads" nil nil "a.baidu.com" " @ads" "ads"]
  (re-matches line-re "include:geolocation-cn") ; => ["include:geolocation-cn" "include:" "include" "geolocation-cn" nil nil]
  )

(def tag-map
  {"ads" :block "cn" :direct "!cn" :proxy})

(defn read-tags
  "Return seq of tags."
  [opts name default-tag]
  (->> (slurp (data-file opts name))
       str/split-lines
       (mapcat
        (fn [line]
          (let [line (-> (first (str/split line #"#" 2)) str/trim)]
            (when-not (str/blank? line)
              (if-let [matches (re-matches line-re line)]
                (case (or (get matches 2) "domain")
                  ("domain" "full") (let [domain (get matches 3)
                                          tag (get matches 5)
                                          tag (get tag-map tag default-tag)]
                                      [[domain tag]])
                  "include" (let [name (get matches 3)]
                              (read-tags opts name default-tag))
                  ;; we don't support regexp yet
                  "regexp" nil
                  (prn {:type :parse-error :line line}))
                (prn {:type :parse-error :line line}))))))))

(defn gen
  [opts]
  (core/write-content
   opts "tags.edn"
   (into {} (concat
             (read-tags opts "cn" :direct)
             (read-tags opts "geolocation-!cn" :proxy)))))
