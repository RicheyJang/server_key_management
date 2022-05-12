# Server Key Management

A MariaDB encryption plugin for [Key Keeper](https://github.com/RicheyJang/key_keeper).

Key keeper: An efficient database remote key management system for database encryption.

## Install

### Linux

1. Install [libhv](https://github.com/ithewei/libhv)

2. Download the `.so` file in [releases](https://github.com/RicheyJang/server_key_management/releases) and put it into the MariaDB plug-in directory.

3. Change my.ini:

```ini
plugin_load_add = server_key_management

server_key_management_url = localhost:7709   # the host and port of key keeper
server_key_management_instance = default     # the instance identifier for the current database
server_key_management_ca_file = /usr/local/share/ca-certificates/ca.crt   # the path of CA certificate
server_key_management_crt_file = /usr/local/share/certs/client/client.crt # the path of Client Certificate
server_key_management_key_file = /usr/local/share/certs/client/client.pem # the path of Client private key file
server_key_management_log_file = /var/log/server_test/plugin.log # the path of log file
```

4. restart MariaDB.

### other OS

#### complile

1. install [libhv](https://github.com/ithewei/libhv)

2. You can put this repository source code into the `plugins` directory of the MariaDB source code, and `cmake`.

3. Enter `plugins/server_key_management` and `make`, get the dynamic link library file.

And then, Install it just like Linux.