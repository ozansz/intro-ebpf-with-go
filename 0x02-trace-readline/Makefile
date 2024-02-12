all: gen compile
.PHONY: all 

gen:
	go generate

compile:
	go build -o trace_readline

clean:
	- rm ebpf_bpf*.go
	- rm ebpf_bpf*.o
	- rm trace_readline
