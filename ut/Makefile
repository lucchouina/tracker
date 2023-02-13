LDFLAGS += -pthread
CFLAGS += -g -O

.PHONY: force

trktest: trktest.c

clean:
	rm trktest

run:
	TRKDEBUG=0 LD_LIBRARY_PATH=../preload:../lib  LD_PRELOAD=libtracker.so gdb ./trktest

install:
