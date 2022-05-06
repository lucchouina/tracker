LIB=libtrkcommon.so
INSTALL_DIR=../install/usr/lib64

OBJS = trkcommon.o
LDFLAGS += -rdynamic -ldl -lpthread
CFLAGS += -DTRACKER -I../lib/include  -fPIC

${LIB}: ${OBJS}
	${CC} -shared -o $@ ${OBJS} ${LDFLAGS}

clean: 
	rm -f ${OBJS} ${LIB}

install: ${LIB}
	install -m 755 -d ${INSTALL_DIR}
	install -m 755 $+ ${INSTALL_DIR}
