DIRS=lib preload mgr
clean_DIRS=$(addprefix clean_,$(DIRS))
install_DIRS=$(addprefix install_,$(DIRS))
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
