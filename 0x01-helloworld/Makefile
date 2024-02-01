all: gen compile
.PHONY: all 

gen:
	go generate

compile:
	go build -o hello_ebpf

clean:
	- rm ebpf_bpf*.go
	- rm ebpf_bpf*.o
	- rm hello_ebpf
