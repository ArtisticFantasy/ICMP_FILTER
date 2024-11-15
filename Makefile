all: icmp_filter_loader

icmp_filter_loader: icmp_filter_loader.c icmp_filter.o
	gcc -o icmp_filter_loader icmp_filter_loader.c -lbpf

icmp_filter.o: icmp_filter.c common.h
	clang -O2 -target bpf -c icmp_filter.c -o icmp_filter.o -I/usr/include/$(shell gcc -dumpmachine)

clean:
	rm -f icmp_filter_loader icmp_filter.o

load: icmp_filter_loader
	sudo ./icmp_filter_loader
	touch loaded

unload: loaded
	sudo rm /sys/fs/bpf/icmp_filter_link
	rm loaded