all: gen compile
.PHONY: all 

gen:
	go generate

compile:
	go build -o packet_count

clean:
	- rm ebpf_bpf*.go
	- rm ebpf_bpf*.o
	- rm packet_count
