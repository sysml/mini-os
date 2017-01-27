################################################################################
# Essential definitions
################################################################################
ifndef XEN_ROOT
$(error "Please define XEN_ROOT")
endif

ifndef LWIP_ROOT
$(error "Please define LWIP_ROOT")
endif

ifndef NEWLIB_ROOT
$(error "Please define NEWLIB_ROOT")
endif

verbose		?= n
debug		?= n

default: all


################################################################################
# Xen and build architecture
################################################################################
XEN_COMPILE_ARCH	?= $(shell uname -m | sed -e s/i.86/x86_32/ -e s/i86pc/x86_32/ -e s/amd64/x86_64/)
XEN_TARGET_ARCH		?= $(XEN_COMPILE_ARCH)

XEN_INTERFACE_VERSION	:= 0x00030205

# Architecture specific variables
ifeq ($(XEN_TARGET_ARCH),x86_32)
GNU_TARGET_ARCH := i686
else
GNU_TARGET_ARCH := $(XEN_TARGET_ARCH)
endif

ifeq ($(findstring x86_,$(XEN_TARGET_ARCH)),x86_)
MINIOS_TARGET_ARCH_FAM := x86
else
$(error "Non x86 target architectures are not yet supported")
endif


################################################################################
# Base commands and functions
################################################################################
LN			 = ln -sf
MKDIR		 = mkdir -p
MV			 = mv -f
RM			 = rm -f
RMDIR		 = rm -rf
TOUCH		 = touch

STRIP		 = strip
OBJCOPY		 = objcopy

CXXCOMPILE	 = $(CXX) $(CDEFINES) $(CINCLUDES) $(CPPFLAGS) $(CXXFLAGS)
CXXLD		 = $(CXX)
CXXLINK		 = $(CXXLD) $(CXXFLAGS) $(LDFLAGS) -o $@
COMPILE		 = $(CC) $(CDEFINES)	 $(CINCLUDES) $(CPPFLAGS) $(CFLAGS)
ASCOMPILE	 = $(CC) $(ASDEFINES) $(CDEFINES) $(CINCLUDES) $(ASFLAGS)
CCLD		 = $(CC)
LINK		 = $(CCLD) $(CFLAGS) $(LDFLAGS) -o $@

ifneq ($(verbose),y)
ccompile				 = @/bin/echo ' ' $(2) $< && $(COMPILE) $(DEPCFLAGS) $(1)
ccompile_nodep			 = @/bin/echo ' ' $(2) $< && $(COMPILE) $(1)
ascompile				 = @/bin/echo ' ' $(2) $< && $(ASCOMPILE) $(DEPCFLAGS) $(1)
ascompile_nodep			 = @/bin/echo ' ' $(2) $< && $(ASCOMPILE) $(1)
cxxcompile				 = @/bin/echo ' ' $(2) $< && $(CXXCOMPILE) $(DEPCFLAGS) $(1)
cxxcompile_nodep		 = @/bin/echo ' ' $(2) $< && $(CXXCOMPILE) $(1)
cxxlink					 = @/bin/echo ' ' $(2) $< && $(CXXLINK) $(1)
archive					 = @/bin/echo ' ' $(2) $@ && $(AR) cr $(1)
x_verbose_cmd			 = $(if $(2),/bin/echo ' ' $(2) $(3) &&,) $(1) $(3)
verbose_cmd				 = @$(x_verbose_cmd)
MAKE					:= $(MAKE) --silent
else
ccompile				 = $(COMPILE) $(DEPCFLAGS) $(1)
ccompile_nodep			 = $(COMPILE) $(1)
ascompile				 = $(ASCOMPILE) $(DEPCFLAGS) $(1)
ascompile_nodep			 = $(ASCOMPILE) $(1)
cxxcompile				 = $(CXXCOMPILE) $(DEPCFLAGS) $(1)
cxxcompile_nodep		 = $(CXXCOMPILE) $(1)
cxxlink					 = $(CXXLINK) $(1)
archive					 = $(AR) crv $(1)
x_verbose_cmd			 = $(1) $(3)
verbose_cmd				 = $(1) $(3)
endif

define add_cc_buildtarget
$1/%.o: $2/%.c | build-reqs
	$$(call ccompile,-c $$< -o $$@,'CC ')
endef

define move-if-changed
if ! cmp -s $(1) $(2); then mv -f $(1) $(2); else rm -f $(1); fi
endef


################################################################################
# Base directory structure
################################################################################
STUBDOM_ROOT		?= $(realpath .)
STUBDOM_BUILD_DIR	?= $(STUBDOM_ROOT)/build

BUILD_DIRS			+= $(STUBDOM_BUILD_DIR)


################################################################################
# MiniOS build configuration
################################################################################
# Defaults
CONFIG_START_NETWORK	?= n
CONFIG_SPARSE_BSS		?= y
CONFIG_QEMU_XS_ARGS		?= n
CONFIG_PCIFRONT			?= n
CONFIG_BLKFRONT			?= y
CONFIG_TPMFRONT			?= n
CONFIG_TPM_TIS			?= n
CONFIG_TPMBACK			?= n
CONFIG_NETMAP			?= n
CONFIG_NETMAP_API		?= 10
CONFIG_NETFRONT			?= y
CONFIG_NETFRONT_POLL		?= n
CONFIG_NETFRONT_POLLTIMEOUT	?= 10000 # usecs
CONFIG_FBFRONT			?= n
CONFIG_KBDFRONT			?= n
CONFIG_CONSFRONT		?= n
CONFIG_CONSFRONT_SYNC		?= n
CONFIG_XENBUS			?= y
CONFIG_XC				?= y
CONFIG_LWIP				?= y
CONFIG_LWIP_NOTHREADS			?= n
CONFIG_LWIP_HEAP_ONLY			?= n
CONFIG_LWIP_POOLS_ONLY			?= n
CONFIG_LWIP_MINIMAL			?= y
CONFIG_LWIP_CHECKSUM_NOGEN		?= n
CONFIG_LWIP_CHECKSUM_NOCHECK		?= n
CONFIG_SHUTDOWN			?= y
CONFIG_PVH				?= y

MINIOS_SRC_DIR		 = $(MINIOS_ROOT)
MINIOS_SUBDIRS		 = lib xenbus console
MINIOS_INCLUDE_DIR	 = $(MINIOS_OBJ_DIR)/include
MINIOS_OBJ_DIR		 = $(STUBDOM_BUILD_DIR)/mini-os
MINIOS_OBJS0-y		:=	\
	console.o			\
	ctype.o				\
	events.o			\
	gntmap.o			\
	gnttab.o			\
	hypervisor.o		\
	kernel.o			\
	lock.o				\
	lwip-arch.o			\
	lwip-net.o			\
	main.o				\
	math.o				\
	mm.o				\
	printf.o			\
	sched.o				\
	shutdown.o			\
	stack_chk_fail.o	\
	string.o			\
	sys.o				\
	xencons_ring.o		\
	xmalloc.o
MINIOS_OBJS0-$(CONFIG_XENBUS)		+= xenbus.o
MINIOS_OBJS0-$(CONFIG_XENBUS)		+= xs.o
MINIOS_OBJS0-$(CONFIG_BLKFRONT)		+= blkfront.o
MINIOS_OBJS0-$(CONFIG_TPMFRONT)		+= tpmfront.o
MINIOS_OBJS0-$(CONFIG_TPM_TIS)		+= tpm_tis.o
MINIOS_OBJS0-$(CONFIG_TPMBACK)		+= tpmback.o
MINIOS_OBJS0-$(CONFIG_FBFRONT)		+= fbfront.o
MINIOS_OBJS0-$(CONFIG_PCIFRONT)		+= pcifront.o
MINIOS_OBJS0-$(CONFIG_CONSFRONT)	+= xencons_bus.o
MINIOS_OBJS0-$(CONFIG_NETFRONT)		+= netfront.o
MINIOS_OPT_FLAGS-$(CONFIG_START_NETWORK)	+= -DCONFIG_START_NETWORK
MINIOS_OPT_FLAGS-$(CONFIG_INCLUDE_START_NETWORK)	+= -DCONFIG_INCLUDE_START_NETWORK
MINIOS_OPT_FLAGS-$(CONFIG_SPARSE_BSS)		+= -DCONFIG_SPARSE_BSS
MINIOS_OPT_FLAGS-$(CONFIG_QEMU_XS_ARGS)		+= -DCONFIG_QEMU_XS_ARGS
MINIOS_OPT_FLAGS-$(CONFIG_PCIFRONT)			+= -DCONFIG_PCIFRONT
MINIOS_OPT_FLAGS-$(CONFIG_NETFRONT)			+= -DCONFIG_NETFRONT
MINIOS_OPT_FLAGS-$(CONFIG_NETMAP)			+= -DCONFIG_NETMAP
MINIOS_OPT_FLAGS-$(CONFIG_BLKFRONT)			+= -DCONFIG_BLKFRONT
MINIOS_OPT_FLAGS-$(CONFIG_TPMFRONT)			+= -DCONFIG_TPMFRONT
MINIOS_OPT_FLAGS-$(CONFIG_TPM_TIS)			+= -DCONFIG_TPM_TIS
MINIOS_OPT_FLAGS-$(CONFIG_TPMBACK)			+= -DCONFIG_TPMBACK
MINIOS_OPT_FLAGS-$(CONFIG_KBDFRONT)			+= -DCONFIG_KBDFRONT
MINIOS_OPT_FLAGS-$(CONFIG_FBFRONT)			+= -DCONFIG_FBFRONT
MINIOS_OPT_FLAGS-$(CONFIG_CONSFRONT)		+= -DCONFIG_CONSFRONT
MINIOS_OPT_FLAGS-$(CONFIG_CONSFRONT_SYNC)	+= -DCONFIG_CONSFRONT_SYNC
MINIOS_OPT_FLAGS-$(CONFIG_XENBUS)			+= -DCONFIG_XENBUS
MINIOS_OPT_FLAGS-$(CONFIG_PVH)				+= -DCONFIG_PVH
MINIOS_OPT_FLAGS-$(CONFIG_DEBUG_MM)			+= -DMM_DEBUG
MINIOS_OPT_FLAGS-$(CONFIG_DEBUG_DFS)		+= -DFS_DEBUG
MINIOS_OPT_FLAGS-$(CONFIG_DEBUG_LIBC)		+= -DLIBC_DEBUG
MINIOS_OPT_FLAGS-$(CONFIG_DEBUG_GNT)		+= -DGNT_DEBUG
MINIOS_OPT_FLAGS-$(CONFIG_DEBUG_GNTMAP)		+= -DGNTMAP_DEBUG
MINIOS_OPT_FLAGS-$(CONFIG_DEBUG_XENBUS)		+= -DXENBUS_DEBUG
MINIOS_OPT_FLAGS-$(CONFIG_DEBUG_LWIP)		+= -DLWIP_DEBUG
MINIOS_OPT_FLAGS-$(CONFIG_DEBUG_LWIP_MALLOC)	+= -DLWIP_DEBUG_MALLOC
ifeq ($(CONFIG_NETFRONT_POLL),y)
MINIOS_OPT_FLAGS-$(CONFIG_NETFRONT) += -DCONFIG_NETFRONT_POLL
MINIOS_OPT_FLAGS-$(CONFIG_NETFRONT) += -DCONFIG_NETFRONT_POLLTIMEOUT=$(CONFIG_NETFRONT_POLLTIMEOUT)
endif

MINIOS_OBJS			 = $(addprefix $(MINIOS_OBJ_DIR)/,$(notdir $(MINIOS_OBJS0-y)))
MINIOS_DEPS			 = $(patsubst %.o,%.d,$(MINIOS_OBJS))
MINIOS_LDLIBS		+= -L$(NEWLIB_ROOT)/lib -whole-archive
MINIOS_LDLIBS		+= -no-whole-archive -lm -lc
MINIOS_LDS			:= $(MINIOS_ROOT)/app.lds

CDEFINES			+= -D__MINIOS__ -D__INSIDE_MINIOS__
CDEFINES			+= $(MINIOS_OPT_FLAGS-y)
CINCLUDES			+= -isystem $(MINIOS_ROOT)/include
CINCLUDES			+= -isystem $(MINIOS_INCLUDE_DIR)
CINCLUDES			+= -isystem $(MINIOS_ROOT)/include/posix
CINCLUDES			+= -isystem $(MINIOS_ROOT)/include/$(MINIOS_TARGET_ARCH_FAM)
CINCLUDES			+= -isystem $(MINIOS_ROOT)/include/$(MINIOS_TARGET_ARCH_FAM)/$(XEN_TARGET_ARCH)
BUILD_DIRS			+= $(MINIOS_INCLUDE_DIR)
BUILD_DIRS			+= $(MINIOS_OBJ_DIR)
DEPS				+= $(MINIOS_DEPS)


MINIOS_TARGET_ARCH_DIR	:= arch/$(MINIOS_TARGET_ARCH_FAM)
MINIOS_ARCH_SRC_DIR		:= $(MINIOS_SRC_DIR)/$(MINIOS_TARGET_ARCH_DIR)
MINIOS_ARCH_INCLUDE_DIR	:= $(MINIOS_OBJ_DIR)/include/$(MINIOS_TARGET_ARCH_FAM)
MINIOS_ARCH_OBJ_DIR		:= $(MINIOS_OBJ_DIR)/arch
MINIOS_ARCH_OBJS0		:=	\
	ioremap.o				\
	mm.o					\
	sched.o					\
	setup.o					\
	time.o					\
	traps.o
MINIOS_ARCH_OBJS		 = $(addprefix $(MINIOS_ARCH_OBJ_DIR)/,$(MINIOS_ARCH_OBJS0))
MINIOS_ARCH_DEPS		 = $(patsubst %.o,%.d,$(MINIOS_ARCH_OBJS))
MINIOS_ARCH_HEAD_OBJ	 = $(MINIOS_ARCH_OBJ_DIR)/$(XEN_TARGET_ARCH).o
MINIOS_ARCH_HEAD_DEPS	 = $(MINIOS_ARCH_HEAD_OBJ:%.o,%.d)
MINIOS_ARCH_LIB0		 = $(XEN_TARGET_ARCH)
MINIOS_ARCH_LIB			 = $(MINIOS_ARCH_OBJ_DIR)/lib$(MINIOS_ARCH_LIB0).a
MINIOS_ARCH_LDLIBS		 = -L$(MINIOS_ARCH_OBJ_DIR) -l$(MINIOS_ARCH_LIB0)
MINIOS_ARCH_LDS			 = $(MINIOS_ARCH_SRC_DIR)/minios-$(XEN_TARGET_ARCH).lds

CINCLUDES				+= -isystem $(MINIOS_ARCH_INCLUDE_DIR)
BUILD_DIRS				+= $(MINIOS_ARCH_INCLUDE_DIR)
BUILD_DIRS				+= $(MINIOS_ARCH_OBJ_DIR)
DEPS					+= $(MINIOS_ARCH_DEPS) $(MINIOS_ARCH_HEAD_DEPS)

# MiniOS links needed for build, UHHH is that ugly :-(
mini-os-links: $(MINIOS_ROOT)/include/list.h build-dirs
	@[ -h $(MINIOS_INCLUDE_DIR)/xen ] ||									\
		($(call x_verbose_cmd,												\
			$(LN) $(XEN_ROOT)/xen/include/public $(MINIOS_INCLUDE_DIR)/xen,	\
			'LN	 $(MINIOS_INCLUDE_DIR)/xen'))
	@[ -h $(MINIOS_INCLUDE_DIR)/mini-os ] ||								\
		($(call x_verbose_cmd,												\
			$(LN) $(MINIOS_ROOT)/include $(MINIOS_INCLUDE_DIR)/mini-os,		\
			'LN	 $(MINIOS_INCLUDE_DIR)/mini-os'))
	@[ -h $(MINIOS_ARCH_INCLUDE_DIR)/mini-os ] ||							\
		($(call x_verbose_cmd,												\
			$(LN) $(MINIOS_ROOT)/include/$(MINIOS_TARGET_ARCH_FAM)			\
			$(MINIOS_ARCH_INCLUDE_DIR)/mini-os,								\
		'LN	 $(MINIOS_ARCH_INCLUDE_DIR)/mini-os'))

# Build rules for MiniOS
$(foreach buildtarget, $(MINIOS_ROOT) $(addprefix $(MINIOS_ROOT)/, $(MINIOS_SUBDIRS)), \
	$(eval $(call add_cc_buildtarget, $(MINIOS_OBJ_DIR), $(buildtarget))))

# We don't put this in build/mini-os/include because it is included as mini-os/list.h
$(MINIOS_ROOT)/include/list.h: $(XEN_ROOT)/tools/include/xen-external/bsd-sys-queue-h-seddery \
							   $(XEN_ROOT)/tools/include/xen-external/bsd-sys-queue.h
	$(call verbose_cmd, perl $^ --prefix=minios >$@.new,'PL $@.new')
	([ -f $@ ] &&  $(call verbose_cmd, move-if-changed,$@.new,$@,'CHK $@.new') ) || mv -f $@.new $@

# Build rules for MiniOS arch lib
$(MINIOS_ARCH_OBJ_DIR)/%.o: $(MINIOS_ARCH_SRC_DIR)/%.c | build-reqs
	$(call ccompile,-c $< -o $@,'CC ')

$(MINIOS_ARCH_OBJ_DIR)/%.o: $(MINIOS_ARCH_SRC_DIR)/%.S | build-reqs
	$(call ascompile,-c $< -o $@,'CC ')

$(MINIOS_ARCH_LIB): $(MINIOS_ARCH_OBJS)
	$(call archive,$@ $^,'AR ')


.PHONY: minios clean-minios clean-minios-links distclean-minios
minios: $(MINIOS_OBJS) $(MINIOS_ARCH_LIB)

clean-minios: clean-minios-links
	$(call verbose_cmd,$(RM)					\
		$(wildcard $(MINIOS_OBJ_DIR)/*.o)		\
		$(wildcard $(MINIOS_OBJ_DIR)/*.d)		\
		$(wildcard $(MINIOS_ARCH_OBJ_DIR)/*.o)	\
		$(wildcard $(MINIOS_ARCH_OBJ_DIR)/*.d),	\
		'CLN $(MINIOS_OBJ_DIR)')

clean-minios-links:
	$(call verbose_cmd,$(RM),'CLN',$(MINIOS_INCLUDE_DIR)/xen)
	$(call verbose_cmd,$(RM),'CLN',$(MINIOS_INCLUDE_DIR)/mini-os)
	$(call verbose_cmd,$(RM),'CLN',$(MINIOS_ARCH_INCLUDE_DIR)/mini-os)

distclean-minios:
	$(call verbose_cmd,$(RMDIR),'CLN',$(MINIOS_OBJ_DIR))

################################################################################
# LWIP
################################################################################
ifeq ($(CONFIG_LWIP),y)
MINIOS_LWIP_SRC_DIR	 = $(LWIP_ROOT)/src/lwip
MINIOS_LWIP_SUBDIRS	 = core core/snmp core/ipv4 core/ipv6 netif netif/ppp api
MINIOS_LWIP_OBJ_DIR	 = $(MINIOS_OBJ_DIR)/lwip

MINIOS_OBJS0-$(CONFIG_LWIP)	+= lwip-net.o		\
				   lwip-arch.o
MINIOS_LWIP_OBJS0 :=	api_msg.o	\
			netifapi.o	\
			err.o		\
			netdb.o		\
			sockets.o	\
			api_lib.o	\
			tcpip.o		\
			netbuf.o	\
			icmp.o		\
			igmp.o		\
			inet_chksum.o	\
			ip4_addr.o	\
			ip4.o		\
			ip_frag.o	\
			tcp_out.o	\
			stats.o		\
			dns.o		\
			pbuf.o		\
			tcp_in.o	\
			sys.o		\
			tcp.o		\
			mem.o		\
			def.o		\
			timers.o	\
			netif.o		\
			init.o		\
			memp.o		\
			dhcp.o		\
			udp.o		\
			raw.o		\
			ethernetif.o	\
			etharp.o

ifneq ($(CONFIG_LWIP_MINIMAL),y)
MINIOS_LWIP_OBJS0 +=  	autoip.o	\
			slipif.o	\
			ppp_oe.o	\
			ppp.o		\
			randm.o		\
			magic.o		\
			ipcp.o		\
			chpms.o		\
			vj.o		\
			md5.o		\
			auth.o		\
			lcp.o		\
			fsm.o		\
			pap.o		\
			chap.o		\
			asn1_enc.o	\
			mib_structs.o	\
			msg_in.o	\
			mib2.o		\
			msg_out.o	\
			asn1_dec.o
endif

MINIOS_LWIP_OBJS	 = $(addprefix $(MINIOS_LWIP_OBJ_DIR)/,$(MINIOS_LWIP_OBJS0))
MINIOS_LWIP_DEPS	 = $(patsubst %.o,%.d,$(MINIOS_LWIP_OBJS))
MINIOS_LWIP_LIB		 = $(MINIOS_LWIP_OBJ_DIR)/liblwip.a

LWIP_OPT_FLAGS-$(CONFIG_LWIP_NOTHREADS)		+= -DCONFIG_LWIP_NOTHREADS
LWIP_OPT_FLAGS-$(CONFIG_LWIP_HEAP_ONLY)		+= -DCONFIG_LWIP_HEAP_ONLY
LWIP_OPT_FLAGS-$(CONFIG_LWIP_POOLS_ONLY)	+= -DCONFIG_LWIP_POOLS_ONLY
LWIP_OPT_FLAGS-$(CONFIG_LWIP_MINIMAL)		+= -DCONFIG_LWIP_MINIMAL
LWIP_OPT_FLAGS-$(CONFIG_LWIP_CHECKSUM_NOGEN)	+= -DCONFIG_LWIP_CHECKSUM_NOGEN
LWIP_OPT_FLAGS-$(CONFIG_LWIP_CHECKSUM_NOCHECK)	+= -DCONFIG_LWIP_CHECKSUM_NOCHECK

CINCLUDES			+= -isystem $(LWIP_ROOT)/include/lwip
CINCLUDES			+= -isystem $(LWIP_ROOT)/include/lwip/ipv4
CINCLUDES			+= -isystem $(LWIP_ROOT)/include/lwip/ipv6
CDEFINES			+= -DHAVE_LWIP
CDEFINES			+= $(LWIP_OPT_FLAGS-y)
BUILD_DIRS			+= $(MINIOS_LWIP_OBJ_DIR)
DEPS				+= $(MINIOS_LWIP_DEPS)

# Build rules for lwip lib
$(foreach buildtarget, $(MINIOS_LWIP_SRC_DIR) \
	$(addprefix $(MINIOS_LWIP_SRC_DIR)/, $(MINIOS_LWIP_SUBDIRS)), \
	$(eval $(call add_cc_buildtarget, $(MINIOS_LWIP_OBJ_DIR), $(buildtarget))))

$(MINIOS_LWIP_LIB): $(MINIOS_LWIP_OBJS)
	$(call archive,$@ $^,'AR ')

.PHONY: lwip clean-lwip distclean-lwip
lwip: $(MINIOS_LWIP_LIB)

clean-lwip:
	$(call verbose_cmd,$(RM)					\
		$(wildcard $(MINIOS_LWIP_OBJ_DIR)/*.o)	\
		$(wildcard $(MINIOS_LWIP_OBJ_DIR)/*.d),	\
		'CLN $(MINIOS_LWIP_OBJ_DIR)')

distclean-lwip:
	$(call verbose_cmd,$(RMDIR),'CLN', $(MINIOS_LWIP_OBJ_DIR))

else

MINIOS_LWIP_LIB		:=
MINIOS_LWIP_OBJS	:=

.PHONY: lwip clean-lwip distclean-lwip
lwip:
clean-lwip:
distclean-lwip:

endif


################################################################################
# General build rules
################################################################################
GCC_INSTALL		= $(shell LANG=C gcc -print-search-dirs | sed -n -e 's/install: \(.*\)/\1/p')

CFLAGS			+= -U __linux__ -U __FreeBSD__ -U __sun__
CFLAGS			+= -nostdinc
CFLAGS			+= -isystem $(GCC_INSTALL)include
CFLAGS			+= -Wall -Wno-format -Wno-redundant-decls -Wno-undef
CFLAGS			+= -fno-builtin -fno-stack-protector -fgnu89-inline

CXXFLAGS		+= -Wall -Wno-format -Wno-redundant-decls -Wno-strict-aliasing -Wno-undef -Wno-pointer-arith
CXXFLAGS		+= -fno-exceptions -fno-rtti -fpermissive -fno-builtin -fno-stack-protector

CDEFINES		+= -DHAVE_LIBC
CDEFINES		+= -D__XEN_INTERFACE_VERSION__=$(XEN_INTERFACE_VERSION)

CINCLUDES		+= -isystem $(XEN_ROOT)/tools/xenstore
CINCLUDES		+= -isystem $(NEWLIB_ROOT)/include

ASDEFINES		+= -D__ASSEMBLY__

LDFLAGS			+= -nostdlib

LDLIBS			+= -L$(NEWLIB_ROOT)/lib -lc -lm

DEPCFLAGS			:= -MD -MP
STUB_GLOBAL_PREFIX	?= xenos_

#
# Architecture special makerules for x86 family
# (including x86_32, x86_32y and x86_64).
#
ifeq ($(XEN_TARGET_ARCH),x86_32)
CFLAGS			+= -m32 -march=i686
CXXFLAGS		+= -m32 -march=i686
ASFLAGS			:= -m32
LDFLAGS			+= -m elf_i386
endif

ifeq ($(XEN_TARGET_ARCH),x86_64)
CFLAGS			+= -m64 -mno-red-zone -fno-reorder-blocks
CFLAGS			+= -fno-asynchronous-unwind-tables
CXXFLAGS		+= -m64 -mno-red-zone -fno-reorder-blocks
CXXFLAGS		+= -fno-asynchronous-unwind-tables
ASFLAGS			+= -m64
LDFLAGS			+= -m elf_x86_64
endif

# Configure debuging
ifeq ($(debug),y)
CFLAGS			+= -g -O0 -fno-omit-frame-pointer -fno-optimize-sibling-calls
CXXFLAGS		+= -g -O0 -fno-omit-frame-pointer -fno-optimize-sibling-calls
else
CFLAGS			+= -O3 -fno-omit-frame-pointer -fno-tree-sra -fno-tree-vectorize
CXXFLAGS		+= -O3 -fno-omit-frame-pointer -fno-tree-sra -fno-tree-vectorize
endif

-include $(DEPS)


################################################################################
# Linking external apps
################################################################################
STUBDOM_NAME		?= stub

STUB_APP_SRC_DIR	?= $(STUBDOM_ROOT)
STUB_APP_OBJ_DIR	?= $(STUBDOM_BUILD_DIR)/$(STUBDOM_NAME)
STUB_APP_OBJS0		?= $(STUBDOM_NAME).o
STUB_APP_OBJS		?= $(addprefix $(STUB_APP_OBJ_DIR)/,$(STUB_APP_OBJS0))
STUB_APP_DEPS		?= $(patsubst %.o,%.d,$(STUB_APP_OBJS))
STUB_LDLIBS			+= $(MINIOS_LDLIBS)

STUB_APP			?= $(STUBDOM_BUILD_DIR)/$(STUBDOM_NAME)
STUB_APP_IMG		?= $(STUBDOM_BUILD_DIR)/$(STUBDOM_NAME)_$(XEN_TARGET_ARCH)

STUB_BANNER			?= banner

CFLAGS				+= $(STUB_CFLAGS)
CPPFLAGS			+= $(STUB_CPPFLAGS)
CINCLUDES			+= $(STUB_CINCLUDES)
CDEFINES			+= $(STUB_CDEFINES)
LDFLAGS				+= $(STUB_LDFLAGS)
ASFLAGS				+= $(STUB_ASFLAGS)
ASDEFINES			+= $(STUB_ASDEFINES)
DEPCFLAGS			+= $(STUB_DEPCFLAGS)
CXXFLAGS			+= $(STUB_CXXFLAGS)
CXXINCLUDES			+= $(STUB_CXXINCLUDES)
CXXDEFINES			+= $(STUB_CXXDEFINES)
BUILD_DIRS			+= $(addprefix $(STUBDOM_BUILD_DIR)/$(STUBDOM_NAME)/, $(STUB_BUILD_DIRS))
BUILD_DIRS			+= $(STUB_APP_OBJ_DIR)
DEPS				+= $(STUB_APP_DEPS)


# Default build for c/c++ stub objects
$(STUB_APP_OBJ_DIR)/%.o: $(STUB_APP_SRC_DIR)/%.c | build-reqs
	$(call ccompile, $(STUB_APP_INCLUDES) -c $< -o $@,'CC ')

$(STUB_APP_OBJ_DIR)/%.o: $(STUB_APP_SRC_DIR)/%.cc | build-reqs
	$(call cxxcompile,$(STUB_APP_INCLUDES) -c $< -o $@,'CXX')

# Default linking for stub objects
$(STUB_APP).o: $(STUB_APP_OBJS) $(MINIOS_LDS)
	$(call verbose_cmd,$(LD) -r -d $(LDFLAGS) -\( $(STUB_APP_OBJS) -\) $(STUB_LDLIBS) -T $(MINIOS_LDS) --undefined main -o,'LD ',$@)

# Linking the image
$(STUB_APP_IMG)_.o: $(MINIOS_ARCH_LIB) $(MINIOS_ARCH_HEAD_OBJ) $(STUB_APP).o $(MINIOS_OBJS) $(MINIOS_LWIP_LIB)
	$(call verbose_cmd,$(LD) -r $(LDFLAGS) $^ $(MINIOS_ARCH_LDLIBS) $(LDLIBS) -o,'LD ',$@)

$(STUB_APP_IMG).o: $(STUB_APP_IMG)_.o
	$(call verbose_cmd,$(OBJCOPY) -w -G $(STUB_GLOBAL_PREFIX)* -G _start $^,'OCP',$@)

$(STUB_APP_IMG): $(STUB_APP_IMG).o
	$(call verbose_cmd,$(LD) $(LDFLAGS) -T $(MINIOS_ARCH_LDS) $@.o -o,'LD ',$@)
ifneq ($(debug),y)
	$(call verbose_cmd,$(STRIP) -s,'STR',$@)
endif

$(STUB_APP_IMG).gz: $(STUB_APP_IMG)
	$(call verbose_cmd,gzip -f -9 -c $? >,GZ,$@)


.PHONY: stub clean-stub distclean-stub
stub: $(STUB_BANNER)
	+$(call verbose_cmd,$(MAKE) DESTDIR= ,'MK ',$(STUB_APP_IMG).gz)
	@echo "================================================================================"
	@echo
	@echo " Your $(STUBDOM_NAME) build is complete..."
	@echo " Get the image from $(STUB_APP_IMG).gz"
	@echo
	@echo "================================================================================"

clean-stub:
	$(call verbose_cmd,$(RM)					\
		$(wildcard $(STUB_APP_OBJ_DIR)/*.o)		\
		$(wildcard $(STUB_APP_OBJ_DIR)/*.d),	\
		'CLN $(STUB_APP_OBJ_DIR)')

distclean-stub:
	$(call verbose_cmd,$(RM)												\
		$(STUB_APP).o $(STUB_APP_IMG).o $(STUB_APP_IMG) $(STUB_APP_IMG).gz,	\
		'CLN $(STUB_APP_IMG)')

.PHONY: banner
banner:
	@#


################################################################################
# Others
################################################################################
.PHONY: all
all: stub


build-reqs-stamp := $(STUBDOM_BUILD_DIR)/build-reqs-stamp
.PHONY: build-reqs
build-reqs: $(build-reqs-stamp) build-dirs
$(build-reqs-stamp):  mini-os-links

.PHONY: build-dirs
build-dirs: $(BUILD_DIRS)
$(BUILD_DIRS):
	$(call verbose_cmd,$(MKDIR),'MKD',$@);


.PHONY: clean
clean: clean-minios clean-lwip clean-stub
distclean: distclean-minios distclean-lwip distclean-stub
	$(call verbose_cmd,$(RMDIR),'CLN',$(STUBDOM_BUILD_DIR))
