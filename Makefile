all:
	gcc  dragonfuzz.c /lib/x86_64-linux-gnu/libaircrack-osdep-1.6.0.so \
		-I/usr/include/ -lm -lcrypto -lssl -lpcap -D_REVISION=\"5.11.17\" -o dragonfuzz

