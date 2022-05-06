LIB=libtracker.so
INSTALL_DIR=../install/usr/lib64

OBJS = trkdbglib.o trkclient.o

LDFLAGS += -ldl -lpthread -ltrkcommon -L../lib
CFLAGS += -I../lib/include -fPIC
CXXFLAGS += -I../lib/include -fPIC

${LIB}: ${OBJS}
	${CXX} -shared -o $@ ${OBJS} ${LDFLAGS}
clean: 
	rm -f ${OBJS} ${LIB}

install: ${LIB}
	install -m 755 -d ${INSTALL_DIR}
	install -m 755 $+ ${INSTALL_DIR}
