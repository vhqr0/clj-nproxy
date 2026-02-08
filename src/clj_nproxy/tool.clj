(ns clj-nproxy.tool
  (:require [clj-nproxy.server :as server]))

(defn start-server
  [opts]
  (server/start-server opts)
  @(promise))
