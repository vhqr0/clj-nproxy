(ns clj-nproxy.server-test
  (:require [clojure.test :refer [deftest is]]
            [clj-nproxy.server :as server]))

(deftest match-tag-test
  (is (= :proxy (server/match-host-tag "google.com" {"google.com" :proxy})))
  (is (= :proxy (server/match-host-tag "www.google.com" {"google.com" :proxy})))
  (is (= :proxy (server/match-host-tag "www.a.google.com" {"google.com" :proxy})))
  (is (= :block (server/match-host-tag "ads.google.com" {"google.com" :proxy "ads.google.com" :block})))
  (is (= nil (server/match-host-tag "baidu.com" {"google.com" :proxy})))
  (is (= :proxy (server/match-client-tag {:host "google.com"} {"google.com" :proxy} :direct)))
  (is (= :proxy (server/match-client-tag {:host "www.google.com"} {"google.com" :proxy} :direct)))
  (is (= :direct (server/match-client-tag {:host "baidu.com"} {"google.com" :proxy} :direct)))
  (is (= nil (server/match-client-tag {:host "ads.google.com" :tag :block} {"google.com" :proxy} :direct)))
  (is (= nil (server/match-client-tag {:host "baidu.com" :tag :direct} {"google.com" :proxy} :direct))))

(deftest thread-test
  (is (= {:type :test/log :inbound {:type :test/tag :inbound {:type :test/proxy}}}
         (-> {:type :thread :inbounds [{:type :test/proxy} {:type :test/tag} {:type :test/log}]}
             server/edn->inbound-opts))))
