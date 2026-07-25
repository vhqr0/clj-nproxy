.PHONY: test
test:
	clojure -X:dev:test

.PHONY: compile
compile:
	clojure -T:build compile

.PHONY: run
run:
	clojure -X:prop-http-host clj-nproxy.cli/start-server

.PHONY: dlc-gen
dlc-gen:
	clojure -X clj-nproxy.tool.dlc/gen

.PHONY: vsub-list
vsub-list:
	clojure -X clj-nproxy.tool.vsub/list

.PHONY: vsub-fetch
vsub-fetch:
	clojure -X clj-nproxy.tool.vsub/fetch

.PHONY: vsub-gen
vsub-gen:
	clojure -X clj-nproxy.tool.vsub/gen
