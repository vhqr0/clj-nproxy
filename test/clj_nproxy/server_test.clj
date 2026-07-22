(ns clj-nproxy.server-test
  (:require [clojure.test :refer [deftest is]]
            [clj-nproxy.server :as server]))

(deftest match-tag-test
  (is (= :proxy (server/match-tag "google.com" {"google.com" :proxy})))
  (is (= :proxy (server/match-tag "www.google.com" {"google.com" :proxy})))
  (is (= :proxy (server/match-tag "www.a.google.com" {"google.com" :proxy})))
  (is (= :block (server/match-tag "ads.google.com" {"google.com" :proxy "ads.google.com" :block})))
  (is (= nil (server/match-tag "baidu.com" {"google.com" :proxy}))))
