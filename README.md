## OpenSSL Configuration on Linux

Because we are using DES (which is considered a legacy algorithm in OpenSSL 3), we have to modify the OpenSSL config to enable legacy providers. This is only needed for the `test_3des.cpp` file.

I got it working the the `openssl.cnf` file (placed in `/etc/ssl`). The important lines are 66 - 72, where we have enabled the legacy provider. 


## OpenSSL Configuration on Mac

I had to do all the steps above, but the location of my `openssl.cnf` needed to be under `/opt/homebrew/etc/openssl@3/openssl.cnf` for it to work on my Mac
