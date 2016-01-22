LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := selinux
LOCAL_SRC_FILES := libselinux.so
include $(PREBUILT_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE    := servicehook
LOCAL_SRC_FILES := servicehook.c

LOCAL_LDLIBS := -llog

LOCAL_SHARED_LIBRARIES := selinux

include $(BUILD_EXECUTABLE)
