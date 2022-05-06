DIRS=lib preload mgr
clean_DIRS=$(addprefix clean_,$(DIRS))
install_DIRS=$(addprefix install_,$(DIRS))
CFLAGS=-O0 -g -m64
CXXFLAGS=-O0 -g -m64
export CFLAGS
export CXXFLAGS
all: $(DIRS)
clean: $(clean_DIRS)
install: $(install_DIRS)
.PHONY: force
$(DIRS): force
	make -C $@
$(clean_DIRS): force
	make -C $(patsubst clean_%,%,$@) clean
	rm -rf install
$(install_DIRS): force
	make -C $(patsubst install_%,%,$@) install

ut: force
	make -C ut
