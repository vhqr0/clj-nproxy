(ns clj-nproxy.tool.dlc-test
  (:require [clojure.test :refer [deftest is]]
            [clj-nproxy.tool.dlc :as dlc]))

(deftest trim-comment-test
  (is (= "foo "
         (dlc/trim-comments "foo # bar")))
  (is (= "foo bar"
         (dlc/trim-comments "foo bar"))))

(deftest line-re-test
  (is (= ["a.baidu.com" nil nil "a.baidu.com" nil nil]
         (re-matches dlc/line-re "a.baidu.com")))
  (is (= ["a.baidu.com @ads" nil nil "a.baidu.com" " @ads" "ads"]
         (re-matches dlc/line-re "a.baidu.com @ads")))
  (is (= ["include:geolocation-cn" "include:" "include" "geolocation-cn" nil nil]
         (re-matches dlc/line-re "include:geolocation-cn"))))
