# android-servicehook
A wrapper to hook a service started from init using LD_PRELOAD.

* Place libselinux.so from your device in the folder `jni`
* Modify the settings in servicehook.c
* Compile using NDK
