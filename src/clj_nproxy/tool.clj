(ns clj-nproxy.tool
  (:require [clj-nproxy.server :as server]))

(defn start-server
  [opts]
  (add-tap prn)
  (server/start-server opts)
  @(promise))
