

UNAME := $(shell uname)

ifeq ($(UNAME), Linux)
    INCLUDE_PATH = /usr/include 
    LIB_PATH = /usr/lib64 
else ifeq ($(UNAME), Darwin)
    INCLUDE_PATH = /opt/homebrew/opt/openssl/include
    LIB_PATH = /opt/homebrew/opt/openssl/lib
else
    OS = "Unknown OS"
endif


all: aes

aes: test_aes.cpp
	g++ -I$(INCLUDE_PATH) -L$(LIB_PATH) -lssl -lcrypto -o test_aes test_aes.cpp 

des: test_des.cpp
	g++ -I$(INCLUDE_PATH) -L$(LIB_PATH) -lssl -lcrypto -o test_des test_des.cpp

3des: test_3des.cpp
	g++ -I$(INCLUDE_PATH) -L$(LIB_PATH) -lssl -lcrypto -o test_3des test_3des.cpp

test: test.cpp
	g++ -I$(INCLUDE_PATH) -L$(LIB_PATH) -lssl -lcrypto -o test test.cpp

outline: outline.cpp
	g++ outline.cpp -I$(INCLUDE_PATH) -L$(LIB_PATH) -lssl -lcrypto

