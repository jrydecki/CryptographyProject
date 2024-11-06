

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


all: main

main: outline.cpp
	g++ outline.cpp -I$(INCLUDE_PATH) -L$(LIB_PATH) -lssl -lcrypto

outline: outline.cpp
	g++ outline.cpp -I$(INCLUDE_PATH) -L$(LIB_PATH) -lssl -lcrypto


