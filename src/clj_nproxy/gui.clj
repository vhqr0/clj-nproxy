(ns clj-nproxy.gui
  (:require [clojure.string :as str]
            [clj-nproxy.cli :as cli])
  (:import [java.time Instant ZoneId LocalDateTime]
           [java.time.format DateTimeFormatter]
           [java.awt BorderLayout FlowLayout]
           [java.awt.event ActionListener WindowListener]
           [javax.swing
            JFrame JPanel JLabel JComboBox
            JScrollPane JTable RowFilter Timer SwingUtilities]
           [javax.swing.table AbstractTableModel TableRowSorter]))

(set! clojure.core/*warn-on-reflection* true)

(defn update-stat
  "Update stat when receive new event."
  [stat log]
  (let [{:keys [level event]} log
        host (when (= event :connect) (get-in log [:req :host]))
        tag (when (= event :pipe) (get-in log [:server :tag]))
        stat (-> stat
                 (update :logs (fnil conj []) log)
                 (update :total (fnil inc 0))
                 (update-in [:levels level] (fnil inc 0))
                 (update-in [:events event] (fnil inc 0)))]
    (cond-> stat
      (some? host) (update-in [:hosts host] (fnil inc 0))
      (some? tag) (update-in [:tags tag] (fnil inc 0)))))

^:rct/test
(comment
  (update-stat nil {:level :info :event :connect :req {:host "foo.bar"}})
  ;; =>
  {:logs   [{:level :info :event :connect :req {:host "foo.bar"}}]
   :total  1
   :levels {:info 1}
   :events {:connect 1}
   :hosts  {"foo.bar" 1}}

  (->> [{:level :info :event :connect :req {:host "foo.bar"}}
        {:level :info :event :pipe :server {:tag "proxy"}}
        {:level :error :event :pipe-error}]
       (reduce update-stat nil))
  ;; =>
  {:logs   [{:level :info :event :connect :req {:host "foo.bar"}}
            {:level :info :event :pipe :server {:tag "proxy"}}
            {:level :error :event :pipe-error}]
   :total  3
   :levels {:info 2 :error 1}
   :events {:connect 1 :pipe 1 :pipe-error 1}
   :hosts  {"foo.bar" 1}
   :tags   {"proxy" 1}})

(def col->data-type [:timestamp :level :event :host :detail])
(def col->data-label ["Time" "Level" "Event" "Host" "Detail"])
(def data-type->data-level (zipmap col->data-type col->data-label))

(defmulti get-display-data-from-log
  "Get display data from log."
  (fn [type _log] type))

(defn get-display-data
  "Get display data at row:col."
  ^String [logs row col]
  (let [log (nth logs row)
        data-type (col->data-type col)]
    (get-display-data-from-log data-type log)))

(defn keyword->display-data
  "Convert keyword to display data."
  [kw]
  (str/upper-case (name kw)))

(def ^:dynamic ^DateTimeFormatter *datetime-formatter*
  (DateTimeFormatter/ofPattern "yyyy-MM-dd HH:mm:ss"))

(defn timestamp->display-data
  "Convert timestamp to display data."
  [timestamp]
  (let [inst (Instant/ofEpochMilli timestamp)
        zone (ZoneId/systemDefault)
        datetime (LocalDateTime/ofInstant inst zone)]
    (.format *datetime-formatter* datetime)))

(defmethod get-display-data-from-log :timestamp [_type log]
  (some-> log :timestamp timestamp->display-data))

(defmethod get-display-data-from-log :level [_type log]
  (some-> log :level keyword->display-data))

(defmethod get-display-data-from-log :event [_type log]
  (some-> log :event keyword->display-data))

(defmethod get-display-data-from-log :host [_type log]
  (some-> log :req :host))

(defmulti get-detail
  "Get detail display data."
  (fn [log] (:event log)))

(defmethod get-display-data-from-log :detail [_type log]
  (get-detail log))

(defmethod get-detail :default [_log])

(defmethod get-detail :pipe [log]
  (or (some-> log :server :name)
      (some-> log :server :tag name)))

(defmethod get-detail :connect-error [log]
  (some-> log :error-str))

(defmethod get-detail :pipe-error [log]
  (some-> log :error-str))

(defn astat->table-model
  "Convert atom stat to table model."
  ^AbstractTableModel [astat]
  (proxy [AbstractTableModel] []
    (getRowCount [] (count (:logs @astat)))
    (getColumnCount [] (count col->data-type))
    (getColumnName [col] (col->data-label col))
    (getValueAt [row col] (str (get-display-data (:logs @astat) row col)))))

(defn astat->gui
  "Convert atom stat to gui."
  [astat]
  (let [frame (JFrame. "nproxy")
        model (astat->table-model astat)
        sorter (TableRowSorter. model)
        table (doto (JTable. model)
                (.setAutoResizeMode JTable/AUTO_RESIZE_LAST_COLUMN)
                (.setFillsViewportHeight true)
                (.setRowSorter sorter))
        scroll-pane (JScrollPane. table)
        level-combo (JComboBox. (object-array ["ALL" "INFO" "ERROR"]))
        event-combo (JComboBox. (object-array ["ALL" "CONNECT" "PIPE" "CONNECT-ERROR" "PIPE-ERROR"]))
        filter-panel (doto (JPanel. (FlowLayout. FlowLayout/LEFT))
                       (.add (JLabel. "Level:"))
                       (.add level-combo)
                       (.add (JLabel. "Event:"))
                       (.add event-combo))
        update-filter-fn (fn []
                           (let [level-filter (let [level (.getSelectedItem level-combo)]
                                                (when-not (= level "ALL")
                                                  (RowFilter/regexFilter (str "^" level "$") (int-array [1]))))
                                 event-filter (let [event (.getSelectedItem event-combo)]
                                                (when-not (= event "ALL")
                                                  (RowFilter/regexFilter (str "^" event "$") (int-array [2]))))
                                 filters (filter some? [level-filter event-filter])
                                 ^RowFilter filter (when (seq filters)
                                                     (if (= 1 (count filters))
                                                       (first filters)
                                                       (RowFilter/andFilter filters)))]
                             (.setRowFilter sorter filter)))
        _ (.addActionListener level-combo
                              (reify ActionListener
                                (actionPerformed [_ _] (update-filter-fn))))
        _ (.addActionListener event-combo
                              (reify ActionListener
                                (actionPerformed [_ _] (update-filter-fn))))
        north-panel (doto (JPanel. (BorderLayout.))
                      (.add filter-panel (BorderLayout/SOUTH)))
        vstat (volatile! @astat)
        timer (Timer. 500
                      (reify ActionListener
                        (actionPerformed [_ _]
                          (let [stat @astat]
                            (when-not (= stat @vstat)
                              (vreset! vstat stat)
                              (.fireTableDataChanged model))))))]
    (doto frame
      (.addWindowListener
       (reify WindowListener
         (windowOpened [_ _] (.start timer))
         (windowClosed [_ _] (.stop timer))
         (windowClosing [_ _] (.stop timer))
         (windowActivated [_ _])
         (windowDeactivated [_ _])))
      (.setLayout (BorderLayout.))
      (.add north-panel BorderLayout/NORTH)
      (.add scroll-pane BorderLayout/CENTER)
      (.setSize 960 640)
      (.setDefaultCloseOperation JFrame/DISPOSE_ON_CLOSE)
      (.setVisible true))))

(defn start-server
  "Start proxy server with gui."
  [opts]
  (let [astat (atom {})]
    (add-tap prn)
    (add-tap #(swap! astat update-stat %))
    (cli/start-server-from-config opts)
    (SwingUtilities/invokeLater #(astat->gui astat))
    @(promise)))
