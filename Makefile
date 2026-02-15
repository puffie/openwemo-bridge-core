SUBDIRS = wemo_ctrl wemo_engine wemo_client

.PHONY: all $(SUBDIRS) test-hardening

all: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@ $(MAKEOVERRIDES)

wemo_client: wemo_engine

clean:
	for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir clean; \
	done

test-hardening: all
	./tests/ipc_negative_test.sh
	./tests/fault_injection_test.sh
