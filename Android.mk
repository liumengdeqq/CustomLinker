LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := Mini_elf_loader
LOCAL_LDLIBS :=-llog
LOCAL_CFLAGS += -DPRELINK
LOCAL_LDFLAGS := -shared
LOCAL_CFLAGS += -fno-stack-protector \
        -Wstrict-overflow=5 \
        -fvisibility=hidden

LOCAL_PRELINK_MODULE := true
LOCAL_SRC_FILES:= \
	linker.c \
	Utils.c \
	linker_format.c \
	rt.c \

LOCAL_CFLAGS += -DLINKER_DEBUG=0

ifeq ($(TARGET_ARCH),arm)
    LOCAL_CFLAGS += -DANDROID_ARM_LINKER
endif
include $(BUILD_SHARED_LIBRARY)