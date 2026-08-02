.PHONY: test
test:
	clojure -X:dev:test

.PHONY: compile
compile:
	clojure -T:build compile

.PHONY: clean
clean:
	clojure -T:build clean

.PHONY: run
run:
	clojure \
		-J-Djdk.httpclient.allowRestrictedHeaders=host \
		-J-Djava.util.logging.config.file=.nproxy/logging.properties \
		-X clj-nproxy.cli/start-server

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

# .PHONY: setup
# setup:
# 	mkdir -p .nproxy/
# 	cp etc/config.edn .nproxy/
# 	cp etc/logging.properties .nproxy/
# 	echo "http://example.com" > .nproxy/sub.url
# 	cd .nproxy && git clone https://github.com/vhqr0/domain-list-community
# 	make dlc-gen
# 	make vsub-fetch
# 	make vsub-gen
