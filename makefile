

UNAME := $(shell uname)

ifeq ($(UNAME), Linux)
    INCLUDE_PATH = /usr/include 
    LIB_PATH = /usr/lib64 
else ifeq ($(UNAME), Darwin)
    INCLUDE_PATH = /opt/homebrew/opt/openssl/include -I/opt/homebrew/opt/crypto++/include
    LIB_PATH = /opt/homebrew/opt/openssl/lib -L/opt/homebrew/opt/crypto++/lib
else
    OS = "Unknown OS"
endif


all: aes des 3des

aes: test_aes.cpp
	g++ -std=c++11 -I$(INCLUDE_PATH) -L$(LIB_PATH) -lssl -lcrypto -o test_aes test_aes.cpp 

des: test_des.cpp
	g++ -std=c++11 -I$(INCLUDE_PATH) -L$(LIB_PATH) -lssl -lcrypto -o test_des test_des.cpp

3des: test_3des.cpp
	g++ -std=c++11 -I$(INCLUDE_PATH) -L$(LIB_PATH) -lssl -lcrypto -o test_3des test_3des.cpp

test: test.cpp
	g++ -std=c++11 -I$(INCLUDE_PATH) -L$(LIB_PATH) -lssl -lcrypto -o test test.cpp

outline: outline.cpp
	g++ -std=c++11 outline.cpp -I$(INCLUDE_PATH) -L$(LIB_PATH) -lssl -lcrypto

