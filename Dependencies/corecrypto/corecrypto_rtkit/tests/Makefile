# Copyright (c) (2024) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

ifeq ($(SDKROOT),)
SDKROOT := $(shell xcrun -sdk iphoneos.internal -show-sdk-path)
endif

ifeq ($(SRCROOT),)
SRCROOT := ../..
endif

ifeq ($(OBJROOT),)
OBJROOT := .
endif

RTKIT_ROOT            = $(SDKROOT)/usr/local/standalone/RTKit

-include $(RTKIT_ROOT)/etc/cortex-m3.mk

RTK_VECTOR_SYMBOL     = _RTK_crt_vectors
PLATFORM              = fastsim_m3
TARG_TEXT_BASE        = 0x00000000
TARG_DATA_BASE        = 0x20000000

CC                    = $(shell xcrun -sdk $(SDKROOT) -find clang)
LD                    = $(shell xcrun -sdk $(SDKROOT) -find ld)
DSYMUTIL              = $(shell xcrun -sdk $(SDKROOT) -find dsymutil)
MACHO_TOOL            = $(RTKIT_ROOT)/usr/bin/macho.py
RTK_POST_PROCESS      = $(RTKIT_ROOT)/usr/bin/rtk_post_process.py

SRCDIR                = $(SRCROOT)/corecrypto_rtkit/tests/src
SRCS                  = $(notdir $(wildcard $(SRCDIR)/*.c))
PROG                  = corecrypto_rtkit_test
BUILDDIR              = $(OBJROOT)/build
INSTALLDIR            = $(DSTROOT)/AppleInternal/Tests/corecrypto/RTKit
SIMDIR                = ./sim
OBJS                  = $(addprefix $(BUILDDIR)/,$(addsuffix .o,$(SRCS)))
MACHO                 = $(BUILDDIR)/$(PROG)
BINFILE               = $(BUILDDIR)/$(PROG).bin
ORDERFILE             = $(BUILDDIR)/$(PROG).order
MAPFILE               = $(BUILDDIR)/$(PROG).map
DSYM                  = $(BUILDDIR)/$(PROG).dSYM
LTOOBJFILE            = $(BUILDDIR)/$(PROG).o

LIBS                  = platform~$(PLATFORM) corecrypto_rtkit

COPTS                 = $(RTK_COMPILE_OPTIONS) \
                        -Oz \
                        -isystem /usr/local/include \
                        -I$(SRCDIR) \
                        -I$(SRCROOT)/cc/corecrypto \
                        -I$(SRCROOT)/cctv/corecrypto \
                        -I$(SRCROOT)/ccpost/corecrypto \
                        -g \
                        -isysroot $(RTKIT_ROOT) \
                        -flto

LDOPTS                = $(RTK_LINK_OPTIONS) \
                        -Wl,-L$(RTKIT_ROOT)/usr/lib/Debug/$(RTK_SLICE) \
                        -Wl,-L$(RTKIT_ROOT)/usr/lib/Release/$(RTK_SLICE) \
                        -Wl,-order_file,$(ORDERFILE) \
                        -Wl,-e,$(RTK_VECTOR_SYMBOL) \
                        -Wl,-map,$(MAPFILE) \
                        -Wl,-segaddr,__TEXT,$(TARG_TEXT_BASE) \
                        -Wl,-segaddr,__DATA,$(TARG_DATA_BASE) \
                        -Wl,-rename_section,__DATA,_rtk_patchbay,__TEXT,_rtk_patchbay \
                        -Wl,-object_path_lto,$(LTOOBJFILE) \
                        $(addprefix -l,$(LIBS))

.PHONY: install
install: $(BUILDDIR) $(MACHO) $(BINFILE)
	install -d $(INSTALLDIR)
	install -C $(MACHO) $(INSTALLDIR)
	install -C $(BINFILE) $(INSTALLDIR)

.PHONY:	run
run:	$(BUILDDIR) $(MACHO) $(BINFILE)
	sh $(RTKIT_ROOT)/etc/$(PLATFORM)/run.sh $(MACHO) $(BINFILE) --session-dir $(SIMDIR)

.PHONY:	rund
rund:	$(BUILDDIR) $(MACHO) $(BINFILE)
	sh $(RTKIT_ROOT)/etc/$(PLATFORM)/run.sh -debug $(MACHO) $(BINFILE) --session-dir $(SIMDIR)

$(BINFILE): $(MACHO)
	$(MACHO_TOOL) -m $< -o $@ -c binary -v

$(MACHO): $(OBJS) $(ORDERFILE) | $(BUILDDIR)
	$(CC) -g -o $@ $(OBJS) $(LDOPTS)
	$(RTKIT_ROOT)/usr/bin/rtk_patchbay.py --file $(MACHO) set RTK_exit_terminates=1
	$(DSYMUTIL) $@
	$(RTK_POST_PROCESS) $@
	$(call rtk-install-lldb-scripts, $@, $(DSYM))

$(filter %.c.o,$(OBJS)): $(BUILDDIR)/%.c.o: $(SRCDIR)/%.c | $(BUILDDIR)
	$(CC) -std=c11 -c $(COPTS) $(<) -o $@

$(filter %.cpp.o,$(OBJS)): $(BUILDDIR)/%.cpp.o: $(SRCDIR)/%.cpp | $(BUILDDIR)
	$(CC) -Drestrict=__restrict -std=c++11 -fno-exceptions -fno-rtti -c $(COPTS) $(<) -o $@

$(BUILDDIR):
	mkdir $@

$(ORDERFILE):	$(MAKEFILE_LIST)
	echo $(RTK_VECTOR_SYMBOL) > $@

.PHONY:	clean
clean:
	rm -rf $(BUILDDIR) $(SIMDIR)
