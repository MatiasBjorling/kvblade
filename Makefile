KVER		:= $(shell uname -r)
KDIR		:= /lib/modules/$(KVER)/build
INSTDIR		:= /lib/modules/$(KVER)/kernel/drivers/block
KMAK_FLAGS	:= \
	CONFIG_KVBLADE=m \
	KDIR=${KDIR}
PWD		:= $(shell pwd)
obj-m		:= kvblade.o

PREFIX		:= 
SBINDIR		:= ${PREFIX}/usr/sbin
MANDIR		:= ${PREFIX}/usr/share/man
CMDS		:= kvstat kvadd kvdel

KVER		:= 4.19.79-tok
KDIR		:= ../tokera/tokkernel/headers.d/build

default: prep
	$(MAKE) -C $(KDIR) M="$(PWD)" SUBDIRS="$(PWD)" modules

prep:
	@test -r "$(KDIR)/.config" || { \
		echo "Error: $(KDIR) sources are not configured." 1>&2; \
		false; \
	}
	@test  -r "$(KDIR)/include/asm-generic" || { \
		echo "Error: $(KDIR) sources are not prepared." 1>&2; \
		false; \
	}
	@printf "ensuring compatibility ... "
	@cd conf && rm -rf *.o *.ko .tmp_versions .*.*o.cmd .*.*o.d *.mod.c
	@sh conf/compat.sh . \
		$(MAKE) -C $(KDIR) $(KMAK_FLAGS) SUBDIRS="$(PWD)/conf" modules

clean:
	rm -rf *.o *.ko *.mod.c .tmp_versions .kvblade*.*o.cmd .kvblade*.*o.d 
	cd conf && rm -rf *.o *.ko .tmp_versions .*.*o.cmd .*.*o.d *.mod.c

install: default
	@echo "Install directory is $(INSTDIR)"
	mkdir -p $(INSTDIR)
	install -m 644 "$(PWD)"/kvblade.ko $(INSTDIR)
	/sbin/depmod -a
	@echo "Installing sysfs interface commands in $(SBINDIR)"
	mkdir -p $(SBINDIR)
	@for f in $(CMDS) ; do \
		sh -xc "install -m 700 $$f ${SBINDIR}/$$f" || break; \
	done

uninstall:
	@echo "Removing module from $(INSTDIR)"
	rm -rf $(INSTDIR)/kvblade.ko
	/sbin/depmod -a
	@echo "Removing sysfs interface commands from $(SBINDIR)"
	@for f in $(CMDS) ; do \
		rm -f ${SBINDIR}/$$f ; \
	done

release: clean
	@for f in conf/*.diff; do \
		patch -p1 -N --no-backup-if-mismatch -r /dev/null <$$f ;\
	done || true
	@sed /^$$/q NEWS

