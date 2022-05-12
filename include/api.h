#ifndef SERVER_KEY_MANAGEMENT_PLUGIN_API_H
#define SERVER_KEY_MANAGEMENT_PLUGIN_API_H

#include <mysql/plugin_encryption.h>
#include "string"
#include "time.h"
#include "hv/hlog.h"
#include "hv/herr.h"
typedef unsigned int uint;
#define MAX_KEY_LENGTH 32

#ifndef HAVE_EncryptAes128Ctr
#define MY_AES_CTR MY_AES_CBC
#endif
#ifndef HAVE_EncryptAes128Gcm
#define MY_AES_GCM MY_AES_CTR
#endif

typedef struct key_info_t {
    uint             id;                  // ID
    uint             version;             // 版本
    unsigned char    key[MAX_KEY_LENGTH]; // 密钥内容
    uint             length;              // 密钥长度
    enum my_aes_mode algorithm;           // 加解密算法
    time_t           timeout;             // 过期时间

    bool is_timeout() {
        return time(0) > timeout;
    }
    bool check_key_valid() {
        if(id == 0 || version == 0 || length == 0 || length > MAX_KEY_LENGTH)
            return false;
        bool all_zero = true;
        for(int i=0;i<MAX_KEY_LENGTH;i++) {
            if(key[i]!=0) {
                all_zero = false;
                break;
            }
        }
        return !all_zero;
    }
    void setAlgorithm(std::string str) {
        if(str == "aes-ecb")
            algorithm = MY_AES_ECB;
        else if(str == "aes-ctr")
            algorithm = MY_AES_CTR;
        else if(str == "aes-gcm")
            algorithm = MY_AES_GCM;
        else
            algorithm = MY_AES_CBC;
    }
} key_info_t;

unsigned int init_client(const char* ca_path, const char* ca_file, const char* crt_file, const char* key_file);
unsigned int del_client();

uint from_server_get_key_info(uint key_id, uint key_version, key_info_t *key);
uint from_server_get_latest_version_key(uint key_id, key_info_t *key);

#endif