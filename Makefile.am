############################################################################
#
# Copyright 2016-2017 Intel Corporation
#
# The source code, information and material ("Material") contained
# herein is owned by Intel Corporation or its suppliers or licensors,
# and title to such Material remains with Intel Corporation or its
# suppliers or licensors. The Material contains proprietary information
# of Intel or its suppliers and licensors. The Material is protected by
# worldwide copyright laws and treaty provisions. No part of the
# Material may be used, copied, reproduced, modified, published,
# uploaded, posted, transmitted, distributed or disclosed in any way
# without Intel's prior express written permission. No license under
# any patent, copyright or other intellectual property rights in the
# Material is granted to or conferred upon you, either expressly, by
# implication, inducement, estoppel or otherwise.  Any license under
# such intellectual property rights must be express and approved by
# Intel in writing.
#
# Unless otherwise agreed by Intel in writing, you may not remove or
# alter this notice or any other notice embedded in Materials by Intel
# or Intel's suppliers or licensors in any way.
#
############################################################################
SYSROOT := $(shell $(CC) --print-sysroot)
lib_LTLIBRARIES = libpam_pod.la
libpam_pod_la_SOURCES = pam_pod.c src/um_pod.c src/hitron/src/um_pod_decode.c \
                       src/hitron/src/um_pod_sha1.c \
                       src/xyssl/library/sha1.c \
                       src/xyssl/library/base64.c \
                       src/xyssl/library/aes.c \
                       src/xyssl/library/padlock.c

AM_CFLAGS = -I ./include -I$(SYSROOT)/usr/include/CC-ARM \
            -I $(SYSROOT)/usr/include/ccsp \
            -I $(SYSROOT)/usr/include/dbus-*/ \
            -I $(SYSROOT)/usr/lib/dbus-*/include \
            -I ./src/hitron/include \
            -I ./src/xyssl/include \
            -include ht_router_systypes.h

AM_LDFLAGS = -lpam -lccsp_common -lpthread

pkgconfigdir = $(libdir)/pkgconfig
