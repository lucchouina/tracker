OBJS = trkmgr.o trkmgrClient.o trkmgrCli.o trkmgrRl.o trkmgrHist.o trkTree.o
LDFLAGS += -lpthread -rdynamic -lcurses -ltrkcommon -L../lib
CFLAGS += -DTRACKER -I../lib/include 
PROG = trackerd
INSTALL_PREFIX=../install

# build
${PROG}: $(OBJS)
	${CC} -o $@ ${OBJS} ${LDFLAGS}

# INSTALL
SRV_DIR=/etc/systemd/system
SRV_FILES=tracker.service
CONF_DIR=/etc
CONF_FILES=tracker.conf
EVO_ENV=015_tracker
EVO_ENV_DIR=/usr/evo/env/common_env.d
PROG_DIR=/usr/bin
UTIL=tracker

install: ${CONF_FILES} ${SRV_FILES} ${ENV_FILES} ${PROG}
	install -m 755 -d ${INSTALL_PREFIX}/${CONF_DIR}
	install -m 755 ${CONF_FILES} ${INSTALL_PREFIX}/${CONF_DIR}
	install -m 755 -d ${INSTALL_PREFIX}/${SRV_DIR}
	install -m 755 ${SRV_FILES} ${INSTALL_PREFIX}/${SRV_DIR}
	install -m 755 -d ${INSTALL_PREFIX}/${ENV_DIR}
	# install -m 755 ${ENV_FILES} ${INSTALL_PREFIX}/${ENV_DIR}
	install -m 755 -d ${INSTALL_PREFIX}/${PROG_DIR}
	install -m 755 ${PROG} ${INSTALL_PREFIX}/${PROG_DIR}
	install -m 755 ${UTIL} ${INSTALL_PREFIX}/${PROG_DIR}
	install -m 755 -d ${INSTALL_PREFIX}/${EVO_ENV_DIR}
	install -m 755 ${EVO_ENV} ${INSTALL_PREFIX}/${EVO_ENV_DIR}
.PHONY: install

clean: 
	rm -f ${OBJS} ${PROG}

run: 
	LD_LIBRARY_PATH=../lib ./trackerd -d -d -d -d -d -d -c tracker.testconf
