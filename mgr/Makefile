OBJS = trkmgr.o trkmgrClient.o trkmgrCli.o trkmgrRl.o trkmgrHist.o trkTree.o addr2line.o
LDFLAGS += -lpthread -rdynamic -lcurses -ltrkcommon -L../lib
CFLAGS += -DTRACKER -I../lib/include -g -O
PROG = trackerd

# build
${PROG}: $(OBJS) addr2line
	${CC} -o $@ ${OBJS} ${LDFLAGS}

# INSTALL
SRV_DIR=/lib/systemd/system
SRV_FILES=tracker.service
CONF_DIR=/usr/conf
CONF_FILES=tracker.conf
EVOSTART=evostart
EVOSTARTDIR=/usr/evo/env/common_env.d
UTIL=tracker

install: ${CONF_FILES} ${SRV_FILES} ${PROG}
	install -m 755 -d ${INSTALL_PREFIX}/${CONF_DIR}
	install -m 644 ${CONF_FILES} ${INSTALL_PREFIX}/${CONF_DIR}
	install -m 755 -d ${INSTALL_PREFIX}/${EVOSTARTDIR}
	install -m 644 ${EVOSTART} ${INSTALL_PREFIX}/${EVOSTARTDIR}/011_tracker
	touch ${INSTALL_PREFIX}/${EVOSTARTDIR}/trackeron
	install -m 755 -d ${INSTALL_PREFIX}/${SRV_DIR}
	install -m 644 ${SRV_FILES} ${INSTALL_PREFIX}/${SRV_DIR}
	install -m 755 -d ${INSTALL_PREFIX}/${ENV_DIR}
	# install -m 755 ${ENV_FILES} ${INSTALL_PREFIX}/${ENV_DIR}
	install -m 755 -d ${INSTALL_PREFIX}/${PROG_DIR}
	install -m 755 ${PROG} ${INSTALL_PREFIX}/${PROG_DIR}
	install -m 755 ${UTIL} ${INSTALL_PREFIX}/${PROG_DIR}
.PHONY: install

clean: 
	rm -f ${OBJS} ${PROG} addr2line_ut.o addr2line

addr2line_ut.o: addr2line.c
	${CC} -c -o $@ $(CFLAGS) $< -DUT

addr2line: addr2line_ut.o
	${CC} -o $@ addr2line_ut.o ../lib/trkcommon.o

runaddr:
	LD_LIBRARY_PATH=../lib gdb ./addr2line

run: 
	LD_LIBRARY_PATH=../lib gdb --args ./trackerd -f -d -d -d -d -d -d -c tracker.testconf
