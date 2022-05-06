LDFLAGS += -pthread

.PHONY: force

all: force trktest
	LD_LIBRARY_PATH=../preload:../lib LD_PRELOAD=libtracker.so ./trktest

trktest: trktest.c

clean:
	rm trktest

install:
