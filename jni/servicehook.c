//**************
// Android Service Hook
//
// Hook a service started on Android init
// Requires setuid bit set to unlink the old socket
//
// Original idea: tobias.waldvogel
//**************

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <selinux/selinux.h>
#include <android/log.h>

#define ANDROID_SOCKET_ENV_PREFIX	"ANDROID_SOCKET_"
#define ANDROID_SOCKET_DIR		"/dev/socket"

#define LOGPREFIX "servicehook"

/* example in init.rc
service exampleservice /system/bin/exampleservice
    user system <--- 1000
    group exampleservice_client <---- 1337
    socket exampleservice stream 0660 system exampleservice_client
    class main
*/

/* SETTINGS */
//mandatory
#define ORIGBINARY "/system/bin/exampleservice.orig"
#define UID 1000
#define GID 1337

//optional
//#define EXECCON ""
#define PRELOADLIB "/system/lib/libexamplepreload.so" //should be in /system
//socket opts
//requires suid bit set on the wrapper
#define SOCKNAME "exampleservice"
#define SOCKTYPE SOCK_STREAM
#define SOCKPERM 0660
#define SOCKUID 1000
#define SOCKGID 1337
#define SOCKSELABEL "u:object_r:exampleservice_socket:s0"
/* SETTINGS END */

//from android/platform/system/core/init/util.c
/*
 * create_socket - creates a Unix domain socket in ANDROID_SOCKET_DIR
 * ("/dev/socket") as dictated in init.rc. This socket is inherited by the
 * daemon. We communicate the file descriptor's value via the environment
 * variable ANDROID_SOCKET_ENV_PREFIX<name> ("ANDROID_SOCKET_foo").
 */
static int create_socket(const char *name, int type, mode_t perm, uid_t uid, gid_t gid)
{
    struct sockaddr_un addr;
    int fd, ret;
    fd = socket(PF_UNIX, type, 0);
    if (fd < 0) {
        __android_log_print(ANDROID_LOG_VERBOSE, LOGPREFIX, "Error: Failed to open socket '%s': %s", name, strerror(errno));
        return -1;
    }
    memset(&addr, 0 , sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), ANDROID_SOCKET_DIR"/%s",
             name);
    ret = unlink(addr.sun_path);
    if (ret != 0 && errno != ENOENT) {
        __android_log_print(ANDROID_LOG_VERBOSE, LOGPREFIX, "Error: Failed to unlink old socket '%s': %s", name, strerror(errno));
        goto out_close;
    }

#ifdef SOCKSELABEL
	setfscreatecon(SOCKSELABEL);
#endif
    ret = bind(fd, (struct sockaddr *) &addr, sizeof (addr));
    if (ret) {
        __android_log_print(ANDROID_LOG_VERBOSE, LOGPREFIX, "Error: Failed to bind socket '%s': %s", name, strerror(errno));
        goto out_unlink;
    }
    setfscreatecon(NULL);

    chown(addr.sun_path, uid, gid);
    chmod(addr.sun_path, perm);
    __android_log_print(ANDROID_LOG_VERBOSE, LOGPREFIX, "Info: Created socket '%s' with mode '%o', user '%d', group '%d'",
         addr.sun_path, perm, uid, gid);
    return fd;
out_unlink:
    unlink(addr.sun_path);
out_close:
    close(fd);
    return -1;
}

//part of android/platform/system/core/init/init.c void service_start(struct service *svc, const char *dynamic_args)
static int compute_context(char** scon)
{
	char *mycon = NULL, *fcon = NULL;
	int rc;
    __android_log_print(ANDROID_LOG_VERBOSE, LOGPREFIX, "Info: computing context for service '%s'", ORIGBINARY);
    rc = getcon(&mycon);
    if (rc < 0) {
        __android_log_print(ANDROID_LOG_VERBOSE, LOGPREFIX, "Error: could not get context while starting '%s'", ORIGBINARY);
        return 1;
    }
    rc = getfilecon(ORIGBINARY, &fcon);
    if (rc < 0) {
        __android_log_print(ANDROID_LOG_VERBOSE, LOGPREFIX, "Error: could not get context while starting '%s'", ORIGBINARY);
        freecon(mycon);
        return 1;
    }
    rc = security_compute_create(mycon, fcon, string_to_security_class("process"), scon);
    freecon(mycon);
    freecon(fcon);
    if (rc < 0) {
        __android_log_print(ANDROID_LOG_VERBOSE, LOGPREFIX, "Error: could not get context while starting '%s'", ORIGBINARY);
        return 1;
    }

	return 0;
}

int main(int argc, char* argv[], char* envp[])
{
	int i;
	int ret = 0;
	char* scon;
	char* args[8];

	__android_log_print(ANDROID_LOG_VERBOSE, LOGPREFIX, "Info: hooking %s", ORIGBINARY);

#ifdef PRELOADLIB
	if(access(PRELOADLIB, F_OK ) != -1)
		setenv("LD_PRELOAD", PRELOADLIB, 1);
#endif

	args[0] = ORIGBINARY;
	for(i = 1;i < argc; i++)
		args[i] = argv[i];
	args[argc] = NULL;

#ifdef SOCKNAME
	{
		int sockfd = -1;
		char sockfdstr[16];
		char* envsock = getenv(ANDROID_SOCKET_ENV_PREFIX SOCKNAME);
		if(envsock != NULL)
		{
			__android_log_print(ANDROID_LOG_VERBOSE, LOGPREFIX, "Info: Found sock in getenv: %s", envsock);
			sockfd = strtol(envsock, NULL, 0);
			if(sockfd == 0)
				__android_log_print(ANDROID_LOG_VERBOSE, LOGPREFIX, "Error: could not read sockfd from env");
			else if(sockfd > 0)
				if(close(sockfd) != 0)
					__android_log_print(ANDROID_LOG_VERBOSE, LOGPREFIX, "Error: could not close old socket %d", sockfd);
		}
		compute_context(&scon);
		setsockcreatecon(scon);

		sockfd = create_socket(SOCKNAME, SOCKTYPE, SOCKPERM, SOCKUID, SOCKGID);

		freecon(scon);
		scon = NULL;
		setsockcreatecon(NULL);

		snprintf(sockfdstr, sizeof(sockfdstr), "%d", sockfd);
		setenv(ANDROID_SOCKET_ENV_PREFIX SOCKNAME, sockfdstr, 1);
		fcntl(sockfd, F_SETFD, 0);
		__android_log_print(ANDROID_LOG_VERBOSE, LOGPREFIX, "Info: New sockfd in getenv: %s", getenv(ANDROID_SOCKET_ENV_PREFIX SOCKNAME));
	}
#endif

#ifdef EXECCON
	setexeccon(EXECCON);
#endif
	setgid(GID);
	setuid(UID);
	__android_log_print(ANDROID_LOG_VERBOSE, LOGPREFIX, "Info: Running original binary %s", ORIGBINARY);
	ret = execv(ORIGBINARY, args);
	if(ret == -1)
		__android_log_print(ANDROID_LOG_VERBOSE, LOGPREFIX, "Error: execv: %s\n", strerror(errno));
	else
		__android_log_print(ANDROID_LOG_VERBOSE, LOGPREFIX, "Info: execv returned with no error");

	return ret;
}