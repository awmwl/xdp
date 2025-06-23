OUTPUT_DIR := $(abspath .build)
LIBBPF_SRC := $(abspath libbpf/src)
LIBBPF_OUT := $(OUTPUT_DIR)/libbpf
BPFTOOL_SRC := $(abspath bpftool/src)
BPFTOOL_OUT := $(OUTPUT_DIR)/bpftool
BIN_DIR := $(OUTPUT_DIR)/bin

.PHONY: all libbpf bpftool install-bpftool clean

all: libbpf bpftool install-bpftool

$(LIBBPF_OUT):
	mkdir -p $@

$(BPFTOOL_OUT):
	mkdir -p $@

$(BIN_DIR):
	mkdir -p $@

libbpf: $(LIBBPF_OUT)
	BUILD_STATIC_ONLY=y OBJDIR=$(LIBBPF_OUT) DESTDIR=$(LIBBPF_OUT) make -C $(LIBBPF_SRC) install

bpftool: $(BPFTOOL_OUT) $(LIBBPF_OUT)
	OUTPUT=$(BPFTOOL_OUT)/ \
	INCLUDES=-I$(LIBBPF_OUT)/include \
	make -C $(BPFTOOL_SRC)

install-bpftool: $(BIN_DIR)
	cp $(BPFTOOL_OUT)/bpftool $(BIN_DIR)/bpftool

clean:
	rm -rf $(OUTPUT_DIR)
