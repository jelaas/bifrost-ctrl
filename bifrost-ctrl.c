/*
 * File: bifrost-ctrl.c
 * Implements:
 *
 * Copyright: Jens Låås UU, 2012
 * Copyright license: According to GPL, see file COPYING in this directory.
 *
 */

/* This is a sample implementation of a libssh based SSH server */
/*
Copyright 2003-2009 Aris Adamantiadis

This file is part of the SSH Library

You are free to copy this file, modify it in any way, consider it being public
domain. This does not apply to the rest of the library though, but it is
allowed to cut-and-paste working code from this file to any license of
program.
The goal is to show the API in action. It's not a reference on how terminal
clients must be made or how a client should react.
*/

#include <libssh/libssh.h>
#include <libssh/server.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sched.h>
#include <poll.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <shadow.h>
#include <sys/klog.h>
#include <unistd.h>
#include <sys/reboot.h>
#include <sys/ioctl.h>
#include <linux/usbdevice_fs.h>
#include <errno.h>
#include <syscall.h>
#define unshare(flags) ((long)syscall(SYS_unshare, flags))

#include "des.h"
#include "md5_crypt.h"
#include "daemonize.h"

#define KBUFSIZE 4096
#define MAX_SALT_LENGTH 32

#ifndef KEYS_FOLDER
#define KEYS_FOLDER "/var/"
//#define KEYS_FOLDER ""
#endif

struct {
	char *port;
	int daemonize;
	int debug;
} conf;

static int ssh_msg(ssh_channel chan, const char *s)
{
	if(!s) return 0;
	return ssh_channel_write(chan, s, strlen(s));
}

static int auth_password(char *user, char *password)
{
	struct spwd *spent;
	FILE *fp;
	char salt[MAX_SALT_LENGTH+1];
	char *cryptpw;
	
	fp = fopen("/var/shadow", "r");
	if(!fp) return 0;
	
	while( (spent = fgetspent(fp)) ) {
		if(!strcmp(spent->sp_namp, "root")) {
			break;
		}
	}
	fclose(fp);
	if(!spent) return 0;

	if(!strncmp(spent->sp_pwdp, "$1$", 3)) {
		char *ep;
		int len;
		
		/* md5 */
		ep = strchr(spent->sp_pwdp+3, '$');
		if(!ep) return 0;
		len = ep - (spent->sp_pwdp + 3);
		if(len > MAX_SALT_LENGTH) return 0;
		strncpy(salt, spent->sp_pwdp+3, len);
		salt[len] = 0;
		cryptpw = crypt_md5(password, salt);
		if(!cryptpw) return 0;		
	} else {
		/* des */
		strncpy(salt, spent->sp_pwdp, 2);
		salt[2] = 0;
		cryptpw = crypt_des(password, salt);
		if(!cryptpw) return 0;
	}
	
	/* compare spent->sp_pwdp */
	if(strcmp(cryptpw, spent->sp_pwdp))
		return 0;

	if(strcmp(user,"root"))
		return 0;
	
	return 1;
}

static int copyfile(const char *src, const char *dst)
{
	int s, d, n;
	char buf[1024];

	s = open(src, O_RDONLY);
	if(s == -1) return -1;
	d = open(dst, O_WRONLY|O_TRUNC|O_CREAT, 0666);
	if(d == -1) return -1;
	
	while( (n = read(s, buf, sizeof(buf))) ) {
		if(n == -1) break;
		write(d, buf, n);
	}
	close(s);
	close(d);
	return 0;
}

static void do_reboot(ssh_channel chan)
{
	char *s = "Reboot...\n";
	ssh_channel_write(chan, s, strlen(s));
	reboot(RB_AUTOBOOT);
	s = "Looks like  the reboot failed..\n";
	ssh_channel_write(chan, s, strlen(s));
}

static void dmesg(ssh_channel chan)
{
	int got;
	char buf[KBUFSIZE];
	
	got = klogctl(3, buf, sizeof(buf)-1);
	if(got < 0)
		return;
	buf[got] = 0;
	ssh_channel_write(chan, buf, got);
}

static int usbresetdev(ssh_channel chan, const char *filename)
{
	int fd, rc;
	
	fd = open(filename, O_WRONLY);
	if (fd == -1) {
		ssh_msg(chan, "INIT: [USB] could not open ");
		ssh_msg(chan, filename);
		ssh_msg(chan, "\n");
		return 1;
	}
	
	rc = ioctl(fd, USBDEVFS_RESET, 0);
	if (rc == -1) {
		if(errno != EISDIR) {
			ssh_msg(chan, "INIT: [USB] ");
			ssh_msg(chan, filename);
			ssh_msg(chan, "reset failed: ");
			ssh_msg(chan, strerror(errno));
		}
		close(fd);
		return 1;
	}
	ssh_msg(chan, "INIT: [USB] ");
	ssh_msg(chan, filename);
	ssh_msg(chan, " reset OK\n");
	
	close(fd);
	return 0;
}


static int usbreset(ssh_channel chan)
{
	char fn[256];
	struct stat statb;
	int bus, dev;
	
	ssh_msg(chan, "INIT: [USB] performing USB reset on all ports\n");
	
	for(bus=1;bus<10;bus++) {
		for(dev=1;dev<10;dev++) {
			sprintf(fn, "/dev/bus/usb/%03d/%03d", bus, dev);
			if(stat(fn, &statb)==0)
				usbresetdev(chan, fn);
		}
	}
	return 0;
}

static void huphandler(int i)
{
	waitpid(-1, NULL, 0);
}

int main(int argc, char **argv){
    ssh_session session;
    ssh_bind sshbind;
    ssh_message message;
    ssh_channel chan=0;
    char buf[2048];
    char line[256];
    int auth=0;
    int sftp=0;
    int i;
    int r;
    int serverfd, rc;

    line[0] = 0;
    conf.port = "23";

    if(argc > 1 && !strcmp(argv[1], "-d"))
	    conf.daemonize = 1;
    if(argc > 1 && !strcmp(argv[1], "-D"))
	    conf.debug = 1;
    if(argc > 1 && !strcmp(argv[1], "-h")) {
	    printf("bifrost-ctrl [-d] [-h]\n");
	    exit(0);
    }

    /* kill any already running instances */
    
    /* unshare filesystem namespace */
    if(unshare(CLONE_NEWNS)) {
	    fprintf(stderr, "unshare failed\n");
	    exit(1);	    
    }

    /* mount tmpfs on /var */
    if(mount("tmpfs", "/var", "tmpfs", 0, "")) {
	    fprintf(stderr, "mount failed\n");
	    exit(1);
    }

    /* copy rsa host key to tmpfs */
    rc = copyfile("/etc/shadow", "/var/shadow");
    rc |= copyfile("/etc/ssh/ssh_host_rsa_key", "/var/ssh_host_rsa_key");
    rc |= copyfile("/etc/ssh/ssh_host_rsa_key.pub", "/var/ssh_host_rsa_key.pub");
    if(rc) {
	    fprintf(stderr, "copy failed: file missing?\n");
	    exit(1);
    }
    
    /* daemonize */
    if(conf.daemonize)
	    daemonize();
        
    /* SIGCHLD handler */
    {
	    struct sigaction act;
	    memset(&act, 0, sizeof(act));
	    act.sa_handler = huphandler;
	    sigaction(SIGCHLD, &act, NULL);
    }

    /* setup libssh */
    sshbind=ssh_bind_new();
    session=ssh_new();

    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, KEYS_FOLDER "ssh_host_rsa_key");

    if(ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT_STR, conf.port) != SSH_OK) {
	    printf("failed to bind to port?\n");
	    exit(1);
    }
    
// on success, SSH_ERROR

    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_LOG_VERBOSITY_STR, "SSH_LOG_NOLOG");

#if 0
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, arg);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, arg);
#endif

    if(ssh_bind_listen(sshbind)<0){
//        printf("Error listening to socket: %s\n",ssh_get_error(sshbind));
        return 1;
    }

    serverfd = ssh_bind_get_fd(sshbind);
    
    while(1) {
	    struct pollfd fds[2];
	    
	    fds[0].fd = serverfd;
	    fds[0].events = POLLIN;
	    fds[0].revents = 0;
	    
	    poll(fds, 1, -1);
    
	    pid_t pid;
	    pid = fork();
	    if(pid > 0) {
		    /* uglyness warning. since we do accept in child, we need to wait a bit */
		    sleep(1);
		    sleep(1);
		    continue;
	    }
	    if(pid == -1) continue;
	    
	    if(conf.debug) printf("%d about to do accept\n", getpid());
	    r=ssh_bind_accept(sshbind,session);
	    if(conf.debug) printf("%d accept done\n", getpid());
	    close(serverfd);
	    if(r==SSH_ERROR){
//		    printf("error accepting a connection : %s\n",ssh_get_error(sshbind));
		    _exit(1);
	    }
	    if (ssh_handle_key_exchange(session)) {
//		    printf("ssh_handle_key_exchange: %s\n", ssh_get_error(session));
		    _exit(1);
	    }
	    do {
		    if(conf.debug) printf("%d waiting for message (preauth)\n", getpid());
		    message=ssh_message_get(session);
		    if(!message)
			    break;
		    switch(ssh_message_type(message)){
		    case SSH_REQUEST_AUTH:
			    switch(ssh_message_subtype(message)){
			    case SSH_AUTH_METHOD_PASSWORD:
				    if(auth_password(ssh_message_auth_user(message),
						     ssh_message_auth_password(message))){
					    auth=1;
					    ssh_message_auth_reply_success(message,0);
					    break;
				    }
				    // not authenticated, send default message
			    case SSH_AUTH_METHOD_NONE:
			    default:
				    ssh_message_auth_set_methods(message,SSH_AUTH_METHOD_PASSWORD);
				    ssh_message_reply_default(message);
				    break;
			    }
			    break;
		    default:
			    ssh_message_reply_default(message);
		    }
		    ssh_message_free(message);
	    } while (!auth);
	    if(!auth){
		    ssh_disconnect(session);
		    _exit(1);
	    }
	    do {
		    if(conf.debug) printf("%d waiting for message (postauth)\n", getpid());
		    message=ssh_message_get(session);
		    if(message){
			    switch(ssh_message_type(message)){
			    case SSH_REQUEST_CHANNEL_OPEN:
				    if(ssh_message_subtype(message)==SSH_CHANNEL_SESSION){
					    chan=ssh_message_channel_request_open_reply_accept(message);
					    break;
				    }
			    default:
				    ssh_message_reply_default(message);
			    }
			    ssh_message_free(message);
		    }
	    } while(message && !chan);
	    if(!chan){
		    ssh_finalize();
		    _exit(1);
	    }
	    do {
		    if(conf.debug) printf("%d waiting for message (postauth2)\n", getpid());
		    message=ssh_message_get(session);
		    if(message && ssh_message_type(message)==SSH_REQUEST_CHANNEL &&
		       ssh_message_subtype(message)==SSH_CHANNEL_REQUEST_SHELL){
//            if(!strcmp(ssh_message_channel_request_subsystem(message),"sftp")){
			    sftp=1;
			    ssh_message_channel_request_reply_success(message);
			    break;
			    //           }
		    }
		    if(!sftp){
			    ssh_message_reply_default(message);
		    }
		    ssh_message_free(message);
	    } while (message && !sftp);
	    if(!sftp){
		    _exit(1);
	    }
	    ssh_msg(chan, "Login complete.\n");
	    while(1) {
		    if(conf.debug) printf("%d waiting for input from channel\n", getpid());
		    i=ssh_channel_read(chan,buf, sizeof(buf)-1, 0);
		    if(conf.debug) printf("%d received input from channel: %d\n", getpid(), i);
		    if(i>0) {
			    buf[i] = 0;
			    if(strlen(line)+strlen(buf) < sizeof(line))
				    strcat(line, buf);
			    else
				    line[0] = 0;
			    if(strchr(line, '\n')) {
				    if(strncmp(line, "exit", 4)==0)
					    break;
				    if(strncmp(line, "quit", 4)==0)
					    break;
				    if(strncmp(line, "help", 4)==0) {
					    char *s = "Available commands:\n"
						    "exit|quit\n"
						    "dmesg\n"
						    "reboot\n"
						    "usbreset\n"
						    "sync\n";
					    ssh_channel_write(chan, s, strlen(s));
				    }
				    if(strncmp(line, "dmesg", 5)==0)
					    dmesg(chan);
				    if(strncmp(line, "reboot", 6)==0)
					    do_reboot(chan);
				    if(strncmp(line, "sync", 4)==0) {
					    ssh_msg(chan, "Syncing filesystems..\n");
					    sync();
					    ssh_msg(chan, "Done\n");
				    }
				    if(strncmp(line, "usbreset", 8)==0)
					    usbreset(chan);
				    line[0] = 0;
			    }
		    }
	    }
	    ssh_disconnect(session);
	    _exit(0);
    }
    ssh_bind_free(sshbind);
    ssh_finalize();
    
    return 0;
}

