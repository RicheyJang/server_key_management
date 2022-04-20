#include <my_global.h>
#include <string.h>
#include "api.h"

/*
  Key Management --------------
*/
static uint get_key_info(uint key_id, uint key_version, key_info_t *key) {
  // TODO better
  return from_server_get_key_info(key_id, key_version, key);
}

static uint get_latest_key_info(uint key_id, key_info_t *key) {
  // TODO better
  return from_server_get_latest_version_key(key_id, key);
}

static uint get_key_latest_version(uint key_id) {
  key_info_t key;
  uint ret = get_latest_key_info(key_id, &key);
  if(ret != 0)
    return ENCRYPTION_KEY_VERSION_INVALID;
  else
    return key.version;
}

static uint get_key_by_id_version(uint key_id, uint key_version,
       unsigned char* dstbuf, uint *buflen) {
  key_info_t key;
  uint ret = get_key_info(key_id, key_version, &key);
  if(ret != 0)
    return ENCRYPTION_KEY_VERSION_INVALID;
  
  if(*buflen < key.length)
    return ENCRYPTION_KEY_BUFFER_TOO_SMALL;

  *buflen= key.length;
  if(dstbuf)
    memcpy(dstbuf, key.key, key.length);
  
  return 0;
}

/* 
  Settings ----------------------
*/
char* url_of_server;
char* instance_identifier;
static char* ca_path;
static char* ca_file;
static char* crt_file;
static char* key_file;
static char* log_file;

static MYSQL_SYSVAR_STR(url, url_of_server,
  PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_READONLY,
  "URL of the remote key management server, format: host:port.",
  NULL, NULL, "127.0.0.1:7709");

static MYSQL_SYSVAR_STR(instance, instance_identifier,
  PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_READONLY,
  "Identifier of the selected key management instance.",
  NULL, NULL, "default");

static MYSQL_SYSVAR_STR(ca_path, ca_path,
  PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_READONLY,
  "Path of the directory containing CA certificates in PEM format.",
  NULL, NULL, "");

static MYSQL_SYSVAR_STR(ca_file, ca_file,
  PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_READONLY,
  "Path and name of the file of CA certificate in PEM format.",
  NULL, NULL, "");

static MYSQL_SYSVAR_STR(crt_file, crt_file,
  PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_READONLY,
  "Path and name of the file of client certificate in PEM format.",
  NULL, NULL, "");

static MYSQL_SYSVAR_STR(key_file, key_file,
  PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_READONLY,
  "Path and name of the file of client private key in PEM format.",
  NULL, NULL, "");

static MYSQL_SYSVAR_STR(log_file, log_file,
  PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_READONLY,
  "Path and name of the operation log file.",
  NULL, NULL, "");

static struct st_mysql_sys_var* settings[] = {
  MYSQL_SYSVAR(url),
  MYSQL_SYSVAR(instance),
  MYSQL_SYSVAR(ca_path),
  MYSQL_SYSVAR(ca_file),
  MYSQL_SYSVAR(crt_file),
  MYSQL_SYSVAR(key_file),
  MYSQL_SYSVAR(log_file),
  NULL
};

/*
  Encryption Functions -----------------
*/

static inline enum my_aes_mode mode(uint key_id, uint key_version, int flags) {
  key_info_t key;
  uint ret = get_key_info(key_id, key_version, &key);
  if(ret != 0) // something goes wrong
    return MY_AES_CBC;
  /*
    If encryption_algorithm is AES_CTR then
      if no-padding, use AES_CTR
      else use AES_GCM (like CTR but appends a "checksum" block)
    else
      use AES_CBC
  */
  if (key.algorithm == MY_AES_GCM)
    if (flags & ENCRYPTION_FLAG_NOPAD)
      return MY_AES_CTR;
    else
      return MY_AES_GCM;
  else
    return key.algorithm;
}

static uint ctx_size(uint key_id, uint key_version) {
  return my_aes_ctx_size(mode(key_id, key_version, 0));
}

static int ctx_init(void *ctx, const unsigned char* key, uint klen,
                    const unsigned char* iv, uint ivlen, int flags,
                    uint key_id, uint key_version) {
  return my_aes_crypt_init(ctx, mode(key_id, key_version, flags), flags, key, klen, iv, ivlen);
}

static int ctx_update(void *ctx, const unsigned char *src, uint slen,
  unsigned char *dst, uint *dlen)
{
  return my_aes_crypt_update(ctx, src, slen, dst, dlen);
}

static int ctx_finish(void *ctx, unsigned char *dst, uint *dlen)
{
  return my_aes_crypt_finish(ctx, dst, dlen);
}

static uint ctx_get_length(uint slen, uint key_id,
                               uint key_version)
{
  return my_aes_get_size(mode(key_id, key_version, 0), slen);
}

/*
  Initial Functions -----------------
*/
static int server_key_management_plugin_init(void *p) {
  if(log_file != NULL && strlen(log_file) > 0) { // 设置日志文件路径
    hlog_set_file(log_file);
  } else { // 关闭日志
    hlog_disable();
  }
  if(init_client(ca_path, ca_file, crt_file, key_file))
    return -1;
  return 0;
}

static int server_key_management_plugin_deinit(void *p) {
  del_client();
  return 0;
}

/*
  Server Key Management Plugin description -----------------
*/
struct st_mariadb_encryption server_key_management_plugin = {
    MariaDB_ENCRYPTION_INTERFACE_VERSION,
    get_key_latest_version,
    get_key_by_id_version,
    ctx_size,
    ctx_init,
    ctx_update,
    ctx_finish,
    ctx_get_length
};

/*
  Plugin library descriptor -----------------
*/
maria_declare_plugin(file_key_management)
{
    MariaDB_ENCRYPTION_PLUGIN,
    &server_key_management_plugin,
    "server_key_management",
    "Richey Jang",
    "MariaDB encryption plugin that uses a remote key management service",
    PLUGIN_LICENSE_GPL,
    server_key_management_plugin_init,
    server_key_management_plugin_deinit,
    0x0100, /* 1.0 */
    NULL,   /* status variables */
    settings,
    "1.0",
    MariaDB_PLUGIN_MATURITY_STABLE
}
maria_declare_plugin_end;
