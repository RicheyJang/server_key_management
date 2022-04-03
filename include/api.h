#ifndef SERVER_KEY_MANAGEMENT_PLUGIN_API_H
#define SERVER_KEY_MANAGEMENT_PLUGIN_API_H

#include "string"
#include "time.h"
#include "hv/hlog.h"
typedef unsigned int uint;
#define MAX_KEY_LENGTH 32

typedef struct key_info_t {
    uint          id;                  // ID
    uint          version;             // 版本
    unsigned char key[MAX_KEY_LENGTH]; // 密钥内容
    uint          length;              // 密钥长度
    std::string   algorithm;           // 加解密算法
    time_t        timeout;             // 过期时间

    bool is_timeout() {
        return time(0) > timeout;
    }
    bool check_key_valid() {
        if(id == 0 || version == 0 || length == 0 || timeout <= 0 || length > MAX_KEY_LENGTH)
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
} key_info_t;

unsigned int init_client(const char* ca_path, const char* ca_file, const char* crt_file, const char* key_file);
unsigned int del_client();



#endif