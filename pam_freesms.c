// PAM module for sms authentication using free sms API.
//
// Copyright 2015 HSC by Deloitte
// Copyright 2015 Patrick Garnier
//
// This is a modified version of the PAM google authenticator module
// This is a modified version of HSC by Deloitte free SMS authenticator module
//
// Copyright 2010 Google Inc.
// Author: Markus Gutschke
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#define _GNU_SOURCE

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pwd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <curl/curl.h>

#ifdef HAVE_SYS_FSUID_H
// We much rather prefer to use setfsuid(), but this function is unfortunately
// not available on all systems.
#include <sys/fsuid.h>
#endif

#ifndef PAM_EXTERN
#define PAM_EXTERN
#endif

#if !defined(LOG_AUTHPRIV) && defined(LOG_AUTH)
#define LOG_AUTHPRIV LOG_AUTH
#endif

#define PAM_SM_AUTH
#include <security/pam_appl.h>
#include <security/pam_modules.h>

#define MODULE_NAME "pam_freesms"
#define SECRET      "~/.freesms"

typedef struct Params {
  const char *secret_filename_spec;
  enum { NULLERR=0, NULLOK, SECRETNOTFOUND } nullok;
  int        echocode;
  int        fixed_uid;
  uid_t      uid;
  int        forward_pass;
  int        debug;
} Params;

#if defined(DEMO) || defined(TESTING)
static char error_msg[128];

const char *get_error_msg(void) __attribute__((visibility("default")));
const char *get_error_msg(void) {
  return error_msg;
}
#endif

static void log_message(int priority, pam_handle_t *pamh,
                        const char *format, ...) {
  char *service = NULL;
  if (pamh)
    pam_get_item(pamh, PAM_SERVICE, (void *)&service);
  if (!service)
    service = "";

  char logname[80];
  snprintf(logname, sizeof(logname), "%s(" MODULE_NAME ")", service);

  va_list args;
  va_start(args, format);
#if !defined(DEMO) && !defined(TESTING)
  openlog(logname, LOG_CONS | LOG_PID, LOG_AUTHPRIV);
  vsyslog(priority, format, args);
  closelog();
#else
  if (!*error_msg) {
    vsnprintf(error_msg, sizeof(error_msg), format, args);
  }
#endif

  va_end(args);

  if (priority == LOG_EMERG) {
    // Something really bad happened. There is no way we can proceed safely.
    _exit(1);
  }
}

static int converse(pam_handle_t *pamh, int nargs,
                    const struct pam_message **message,
                    struct pam_response **response) {
  struct pam_conv *conv;
  int retval = pam_get_item(pamh, PAM_CONV, (void *)&conv);
  if (retval != PAM_SUCCESS) {
    return retval;
  }
  return conv->conv(nargs, message, response, conv->appdata_ptr);
}

static const char *get_user_name(pam_handle_t *pamh, const Params *params) {
  // Obtain the user's name
  const char *username;
  if (pam_get_item(pamh, PAM_USER, (void *)&username) != PAM_SUCCESS ||
      !username || !*username) {
    log_message(LOG_ERR, pamh,
                "No user name available when checking verification code");
    return NULL;
  }
  if (params->debug) {
    log_message(LOG_INFO, pamh, "debug: start of freesms for %s", username);
  }
  return username;
}

static char *get_secret_filename(pam_handle_t *pamh, const Params *params,
                                 const char *username, int *uid) {
  // Check whether the administrator decided to override the default location
  // for the secret file.
  const char *spec = params->secret_filename_spec
    ? params->secret_filename_spec : SECRET;

  // Obtain the user's id and home directory
  struct passwd pwbuf, *pw = NULL;
  char *buf = NULL;
  char *secret_filename = NULL;
  if (!params->fixed_uid) {
    #ifdef _SC_GETPW_R_SIZE_MAX
    int len = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (len <= 0) {
      len = 4096;
    }
    #else
    int len = 4096;
    #endif
    buf = malloc(len);
    *uid = -1;
    if (buf == NULL ||
        getpwnam_r(username, &pwbuf, buf, len, &pw) ||
        !pw ||
        !pw->pw_dir ||
        *pw->pw_dir != '/') {
    err:
      log_message(LOG_ERR, pamh, "Failed to compute location of secret file");
      free(buf);
      free(secret_filename);
      return NULL;
    }
  }

  // Expand filename specification to an actual filename.
  if ((secret_filename = strdup(spec)) == NULL) {
    goto err;
  }
  int allow_tilde = 1;
  for (int offset = 0; secret_filename[offset];) {
    char *cur = secret_filename + offset;
    char *var = NULL;
    size_t var_len = 0;
    const char *subst = NULL;
    if (allow_tilde && *cur == '~') {
      var_len = 1;
      if (!pw) {
        goto err;
      }
      subst = pw->pw_dir;
      var = cur;
    } else if (secret_filename[offset] == '$') {
      if (!memcmp(cur, "${HOME}", 7)) {
        var_len = 7;
        if (!pw) {
          goto err;
        }
        subst = pw->pw_dir;
        var = cur;
      } else if (!memcmp(cur, "${USER}", 7)) {
        var_len = 7;
        subst = username;
        var = cur;
      }
    }
    if (var) {
      size_t subst_len = strlen(subst);
      char *resized = realloc(secret_filename,
                              strlen(secret_filename) + subst_len);
      if (!resized) {
        goto err;
      }
      var += resized - secret_filename;
      secret_filename = resized;
      memmove(var + subst_len, var + var_len, strlen(var + var_len) + 1);
      memmove(var, subst, subst_len);
      offset = var + subst_len - resized;
      allow_tilde = 0;
    } else {
      allow_tilde = *cur == '/';
      ++offset;
    }
  }

  *uid = params->fixed_uid ? params->uid : pw->pw_uid;
  free(buf);
  return secret_filename;
}

static int setuser(int uid) {
#ifdef HAVE_SETFSUID
  // The semantics for setfsuid() are a little unusual. On success, the
  // previous user id is returned. On failure, the current user id is returned.
  int old_uid = setfsuid(uid);
  if (uid != setfsuid(uid)) {
    setfsuid(old_uid);
    return -1;
  }
#else
#ifdef linux
#error "Linux should have setfsuid(). Refusing to build."
#endif
  int old_uid = geteuid();
  if (old_uid != uid && seteuid(uid)) {
    return -1;
  }
#endif
  return old_uid;
}

static int setgroup(int gid) {
#ifdef HAS_SETFSUID
  // The semantics of setfsgid() are a little unusual. On success, the
  // previous group id is returned. On failure, the current groupd id is
  // returned.
  int old_gid = setfsgid(gid);
  if (gid != setfsgid(gid)) {
    setfsgid(old_gid);
    return -1;
  }
#else
  int old_gid = getegid();
  if (old_gid != gid && setegid(gid)) {
    return -1;
  }
#endif
  return old_gid;
}

static int drop_privileges(pam_handle_t *pamh, const char *username, int uid,
                           int *old_uid, int *old_gid) {
  // Try to become the new user. This might be necessary for NFS mounted home
  // directories.

  // First, look up the user's default group
  #ifdef _SC_GETPW_R_SIZE_MAX
  int len = sysconf(_SC_GETPW_R_SIZE_MAX);
  if (len <= 0) {
    len = 4096;
  }
  #else
  int len = 4096;
  #endif
  char *buf = malloc(len);
  if (!buf) {
    log_message(LOG_ERR, pamh, "Out of memory");
    return -1;
  }
  struct passwd pwbuf, *pw;
  if (getpwuid_r(uid, &pwbuf, buf, len, &pw) || !pw) {
    log_message(LOG_ERR, pamh, "Cannot look up user id %d", uid);
    free(buf);
    return -1;
  }
  gid_t gid = pw->pw_gid;
  free(buf);

  int gid_o = setgroup(gid);
  int uid_o = setuser(uid);
  if (uid_o < 0) {
    if (gid_o >= 0) {
      if (setgroup(gid_o) < 0 || setgroup(gid_o) != gid_o) {
        // Inform the caller that we were unsuccessful in resetting the group.
        *old_gid = gid_o;
      }
    }
    log_message(LOG_ERR, pamh, "Failed to change user id to \"%s\"",
                username);
    return -1;
  }
  if (gid_o < 0 && (gid_o = setgroup(gid)) < 0) {
    // In most typical use cases, the PAM module will end up being called
    // while uid=0. This allows the module to change to an arbitrary group
    // prior to changing the uid. But there are many ways that PAM modules
    // can be invoked and in some scenarios this might not work. So, we also
    // try changing the group _after_ changing the uid. It might just work.
    if (setuser(uid_o) < 0 || setuser(uid_o) != uid_o) {
      // Inform the caller that we were unsuccessful in resetting the uid.
      *old_uid = uid_o;
    }
    log_message(LOG_ERR, pamh,
                "Failed to change group id for user \"%s\" to %d", username,
                (int)gid);
    return -1;
  }

  *old_uid = uid_o;
  *old_gid = gid_o;
  return 0;
}

static int open_secret_file(pam_handle_t *pamh, const char *secret_filename,
                            struct Params *params, const char *username,
                            int uid, off_t *size, time_t *mtime) {
  // Try to open "~/.freesms"
  *size = 0;
  *mtime = 0;
  int fd = open(secret_filename, O_RDONLY);
  struct stat sb;
  if (fd < 0 ||
      fstat(fd, &sb) < 0) {
    if (params->nullok != NULLERR && errno == ENOENT) {
      // The user doesn't have a state file, but the administrator said
      // that this is OK. We still return an error from open_secret_file(),
      // but we remember that this was the result of a missing state file.
      params->nullok = SECRETNOTFOUND;
    } else {
      log_message(LOG_ERR, pamh, "Failed to read \"%s\"", secret_filename);
    }
 error:
    if (fd >= 0) {
      close(fd);
    }
    return -1;
  }

  // Check permissions on "~/.freesms"
  if ((sb.st_mode & 03577) != 0400 ||
      !S_ISREG(sb.st_mode) ||
      sb.st_uid != (uid_t)uid) {
    char buf[80];
    if (params->fixed_uid) {
      sprintf(buf, "user id %d", params->uid);
      username = buf;
    }
    log_message(LOG_ERR, pamh,
                "Secret file \"%s\" must only be accessible by %s",
                secret_filename, username);
    goto error;
  }

  // Sanity check for file length
  // user is 8 digits, api key is 14 chars + one \n separator
  // Allow a \n at the end of the file
  if (sb.st_size < 23 || sb.st_size > 25) {
    log_message(LOG_ERR, pamh,
                "Invalid file size for \"%s\" %u", secret_filename, sb.st_size);
    goto error;
  }

  *size = sb.st_size;
  *mtime = sb.st_mtime;
  return fd;
}

static char *read_file_contents(pam_handle_t *pamh,
                                const Params *params,
                                const char *secret_filename, int *fd,
                                off_t filesize) {
  // Read file contents
  char *buf = malloc(filesize + 1);
  if (!buf ||
      read(*fd, buf, filesize) != filesize) {
    close(*fd);
    *fd = -1;
    log_message(LOG_ERR, pamh, "Could not read \"%s\"", secret_filename);
 error:
    if (buf) {
      memset(buf, 0, filesize);
      free(buf);
    }
    return NULL;
  }
  close(*fd);
  *fd = -1;

  // The rest of the code assumes that there are no NUL bytes in the file.
  if (memchr(buf, 0, filesize)) {
    log_message(LOG_ERR, pamh, "Invalid file contents in \"%s\"",
                secret_filename);
    goto error;
  }

  // Terminate the buffer with a NUL byte.
  buf[filesize] = '\000';

  if(params->debug) {
    log_message(LOG_INFO, pamh, "debug: \"%s\" read", secret_filename);
  }
  return buf;
}

static char *request_pass(pam_handle_t *pamh, int echocode,
                          const char *prompt) {
  // Query user for verification code
  const struct pam_message msg = { .msg_style = echocode,
                                   .msg       = prompt };
  const struct pam_message *msgs = &msg;
  struct pam_response *resp = NULL;
  int retval = converse(pamh, 1, &msgs, &resp);
  char *ret = NULL;
  if (retval != PAM_SUCCESS || resp == NULL || resp->resp == NULL ||
      *resp->resp == '\000') {
    log_message(LOG_ERR, pamh, "Did not receive verification code from user");
    if (retval == PAM_SUCCESS && resp && resp->resp) {
      ret = resp->resp;
    }
  } else {
    ret = resp->resp;
  }

  // Deallocate temporary storage
  if (resp) {
    if (!ret) {
      free(resp->resp);
    }
    free(resp);
  }

  return ret;
}

static int parse_user(pam_handle_t *pamh, const char *name, uid_t *uid) {
  char *endptr;
  errno = 0;
  long l = strtol(name, &endptr, 10);
  if (!errno && endptr != name && l >= 0 && l <= INT_MAX) {
    *uid = (uid_t)l;
    return 0;
  }
  #ifdef _SC_GETPW_R_SIZE_MAX
  int len   = sysconf(_SC_GETPW_R_SIZE_MAX);
  if (len <= 0) {
    len = 4096;
  }
  #else
  int len   = 4096;
  #endif
  char *buf = malloc(len);
  if (!buf) {
    log_message(LOG_ERR, pamh, "Out of memory");
    return -1;
  }
  struct passwd pwbuf, *pw;
  if (getpwnam_r(name, &pwbuf, buf, len, &pw) || !pw) {
    free(buf);
    log_message(LOG_ERR, pamh, "Failed to look up user \"%s\"", name);
    return -1;
  }
  *uid = pw->pw_uid;
  free(buf);
  return 0;
}

static int parse_args(pam_handle_t *pamh, int argc, const char **argv,
                      Params *params) {
  params->debug = 0;
  params->echocode = PAM_PROMPT_ECHO_OFF;
  for (int i = 0; i < argc; ++i) {
    if (!memcmp(argv[i], "secret=", 7)) {
      free((void *)params->secret_filename_spec);
      params->secret_filename_spec = argv[i] + 7;
    } else if (!memcmp(argv[i], "user=", 5)) {
      uid_t uid;
      if (parse_user(pamh, argv[i] + 5, &uid) < 0) {
        return -1;
      }
      params->fixed_uid = 1;
      params->uid = uid;
    } else if (!strcmp(argv[i], "debug")) {
      params->debug = 1;
    } else if (!strcmp(argv[i], "forward_pass")) {
      params->forward_pass = 1;
    } else if (!strcmp(argv[i], "nullok")) {
      params->nullok = NULLOK;
    } else if (!strcmp(argv[i], "echo-verification-code") ||
               !strcmp(argv[i], "echo_verification_code")) {
      params->echocode = PAM_PROMPT_ECHO_ON;
    } else {
      log_message(LOG_ERR, pamh, "Unrecognized option \"%s\"", argv[i]);
      return -1;
    }
  }
  return 0;
}

static int send_code(pam_handle_t *pamh, char *user, char *pass, long secret,
                     Params *params) {

  CURL *curl;
  CURLcode res;
  long http_code;
  int error = 0;

  curl_global_init(CURL_GLOBAL_ALL);

  curl = curl_easy_init();
  if(curl) {
    char url[256];
    char *msg = "Code (";
    char msg2[32];
    char *msg3 = "): ";
    char *msg4 = "Verification Code: ";
    char *e_user, *e_pass, *e_msg, *e_msg3, *e_msg4;
    int z;
    e_user = curl_easy_escape(curl, user, 0);
    e_pass = curl_easy_escape(curl, pass, 0);
    e_msg = curl_easy_escape(curl, msg, 0);
    e_msg3 = curl_easy_escape(curl, msg3, 0);
    e_msg4 = curl_easy_escape(curl, msg4, 0);

    z = gethostname(msg2,sizeof msg2);
    
    if ( z == -1 ) {
       snprintf(url, 256,
        "https://smsapi.free-mobile.fr/sendmsg?user=%s&pass=%s&msg=%s%06ld",
        e_user, e_pass, e_msg4, secret);
    }
    else {
       snprintf(url, 256,
        "https://smsapi.free-mobile.fr/sendmsg?user=%s&pass=%s&msg=%s%s%s%06ld",
        e_user, e_pass, e_msg, msg2, e_msg3, secret);
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    res = curl_easy_perform(curl);
    if(res != CURLE_OK) {
      log_message(LOG_ERR, pamh, "curl error: \"%s\"", curl_easy_strerror(res));
      error = 1;
    } else {
      curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
      if (http_code != 200) {
        log_message(LOG_ERR, pamh, "free api error: %ld", http_code);
        error = 1;
      }
    }
    curl_easy_cleanup(curl);
  }

  curl_global_cleanup();

  if (params->debug && !error) {
    log_message(LOG_INFO, pamh, "debug: sent code %ld", secret );
  }
  return error;
}

static long generate_secret(pam_handle_t *pamh, Params *params) {
  char *file_name = "/dev/urandom";
  int f;

  f = open(file_name, O_RDONLY);

  if( f == -1 )
  {
    log_message(LOG_ERR, pamh, "Cannot generate random from /dev/urandom");
    return -1;
  }

  // We need a 6 digits random number.
  // Generate 20bits random numbers until one of them is in the good range.
  long secret;
  uint32_t sec;
  do {
    read(f, &sec, sizeof(uint32_t));
    secret = (long) sec>>12;
  } while((secret > 999999) || (secret < 100000));

  close(f);

  if (params->debug) {
    log_message(LOG_INFO, pamh, "debug: sent generated secret %ld", secret );
  }
  return secret;
}

static int freesms(pam_handle_t *pamh, int flags, int argc,
                   const char **argv) {
  int        rc = PAM_AUTH_ERR;
  const char *username;
  char       *secret_filename = NULL;
  int        uid = -1, old_uid = -1, old_gid = -1, fd = -1;
  off_t      filesize = 0;
  time_t     mtime = 0;
  char       *buf = NULL;

#if defined(DEMO) || defined(TESTING)
  *error_msg = '\000';
#endif

  // Handle optional arguments that configure our PAM module
  Params params = { 0 };
  if (parse_args(pamh, argc, argv, &params) < 0) {
    return rc;
  }

  // Read and process status file, then ask the user for the verification code.
  if ((username = get_user_name(pamh, &params)) &&
      (secret_filename = get_secret_filename(pamh, &params, username, &uid)) &&
      !drop_privileges(pamh, username, uid, &old_uid, &old_gid) &&
      (fd = open_secret_file(pamh, secret_filename, &params, username, uid,
                             &filesize, &mtime)) >= 0 &&
      (buf = read_file_contents(pamh, &params, secret_filename, &fd, filesize)) ) {
    char *pw = NULL, *saved_pw = NULL;
    char *user = NULL, *apikey = NULL;
    long secret;

    user = strtok(buf,"\n");
    if (user != NULL) {
      apikey = strtok(NULL, "\n");
    }

    if (user == NULL || apikey == NULL || (strtok(NULL,"\n") != NULL)) {
      log_message(LOG_ERR, pamh, "Error parsing the file");
      // original google authenticator code used a continue to deal with error.
      // We don't need a loop so a simple goto out of the if is the simplest
      // way here, albeit far from the cleanest.
      goto cleanup;
    }

    secret = generate_secret(pamh, &params);

    if (send_code(pamh, user, apikey, secret, &params) < 0) {
      goto cleanup;
    }

    saved_pw = request_pass(pamh, params.echocode,
        params.forward_pass ?
        "Password & verification code: " :
        "Verification code: ");
    
    if (saved_pw) {
      pw = strdup(saved_pw);
    }

    if (!pw) {
      goto cleanup;
    }

    // We are often dealing with a combined password and verification
    // code. Separate them now.
    int pw_len = strlen(pw);
    int expected_len = 6;
    char ch;
    if (pw_len < expected_len ||
        // Verification codes are six digits starting with '0'..'9',
        (ch = pw[pw_len - expected_len]) > '9' ||
        ch < '0') {
    invalid:
      memset(pw, 0, pw_len);
      free(pw);
      pw = NULL;
      goto cleanup;
    }
    char *endptr;
    errno = 0;
    long l = strtol(pw + pw_len - expected_len, &endptr, 10);
    if (errno || l < 0 || *endptr) {
      goto invalid;
    }
    int code = (int)l;
    memset(pw + pw_len - expected_len, 0, expected_len);

    if ( !params.forward_pass) {
      // We are explicitly configured so that we don't try to share
      // the password with any other stacked PAM module. We must
      // therefore verify that the user entered just the verification
      // code, but no password.
      if (*pw) {
        goto invalid;
      }
    }

    // check the verification code
    if (code == (int) secret) {
      rc = PAM_SUCCESS;
    }

    // Update the system password, if we were asked to forward
    // the system password. We already removed the verification
    // code from the end of the password.
    if (rc == PAM_SUCCESS && params.forward_pass) {
      if (!pw || pam_set_item(pamh, PAM_AUTHTOK, pw) != PAM_SUCCESS) {
        rc = PAM_AUTH_ERR;
      }
    }

    // Clear out password and deallocate memory
    if (pw) {
      memset(pw, 0, strlen(pw));
      free(pw);
    }
    if (saved_pw) {
      memset(saved_pw, 0, strlen(saved_pw));
      free(saved_pw);
    }

    // If nothing matched, display an error message
    if (rc != PAM_SUCCESS) {
      log_message(LOG_ERR, pamh, "Invalid verification code");
    }
  }

cleanup:
  // If the user has not created a state file with a shared secret, and if
  // the administrator set the "nullok" option, this PAM module completes
  // successfully, without ever prompting the user.
  if (params.nullok == SECRETNOTFOUND) {
    rc = PAM_SUCCESS;
  }

  if (fd >= 0) {
    close(fd);
  }
  if (old_gid >= 0) {
    if (setgroup(old_gid) >= 0 && setgroup(old_gid) == old_gid) {
      old_gid = -1;
    }
  }
  if (old_uid >= 0) {
    if (setuser(old_uid) < 0 || setuser(old_uid) != old_uid) {
      log_message(LOG_EMERG, pamh, "We switched users from %d to %d, "
                  "but can't switch back", old_uid, uid);
    }
  }
  free(secret_filename);

  // Clean up
  if (buf) {
    memset(buf, 0, strlen(buf));
    free(buf);
  }
  return rc;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv) {
  return freesms(pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
                              const char **argv) {
  return PAM_SUCCESS;
}

#ifdef PAM_STATIC
struct pam_module _pam_listfile_modstruct = {
  MODULE_NAME,
  pam_sm_authenticate,
  pam_sm_setcred,
  NULL,
  NULL,
  NULL,
  NULL
};
#endif
