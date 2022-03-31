#include <my_global.h>
#include <typelib.h>
#include <mysql/plugin_encryption.h>
#include <string.h>
typedef unsigned int uint;

/*
  Key Management --------------
*/
static uint get_key_latest_version(uint key_id) {
    // TODO implement me
    return ENCRYPTION_KEY_VERSION_INVALID;
}

static uint get_key_by_id_version(uint key_id, uint key_version,
       unsigned char* dstbuf, uint *buflen) {
    // TODO implement me
    return ENCRYPTION_KEY_VERSION_INVALID;
}

/*
  Settings ----------------------
*/
static char* url;

static MYSQL_SYSVAR_STR(url, url,
  PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_READONLY,
  "URL of the remote key management server, format: host:port.",
  NULL, NULL, "127.0.0.1:7709");

static struct st_mysql_sys_var* settings[] = {
  MYSQL_SYSVAR(url),
  NULL
};

/*
  Encryption Functions -----------------
*/
#ifndef HAVE_EncryptAes128Ctr
#define MY_AES_CTR MY_AES_CBC
#endif
#ifndef HAVE_EncryptAes128Gcm
#define MY_AES_GCM MY_AES_CTR
#endif

static inline enum my_aes_mode mode(uint key_id, uint key_version, int flags) {
  /*
    TODO get the Algorithm By Key Info

    old: 

    If encryption_algorithm is AES_CTR then
      if no-padding, use AES_CTR
      else use AES_GCM (like CTR but appends a "checksum" block)
    else
      use AES_CBC
  */
  return MY_AES_CBC;
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
    return 0;
}

static int server_key_management_plugin_deinit(void *p) {
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
    MariaDB_PLUGIN_MATURITY_EXPERIMENTAL // TODO to stable
}
maria_declare_plugin_end;
