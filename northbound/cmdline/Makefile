############################################################
# FastRG makefile
############################################################

######################################
# Set variable
######################################	
CC = gcc
INCLUDE = -I../../src -I../grpc
CFLAGS = $(INCLUDE) -Wall -g $(shell pkg-config --cflags libdpdk) -O3 -DALLOW_EXPERIMENTAL_API -DTEST_MODE #-Wextra -fsanitize=address

LDFLAGS = $(shell pkg-config --static --libs libdpdk) -lutils -lconfig -Wl,--start-group -lstdc++ $(shell pkg-config --libs grpc++ protobuf) -laddress_sorting -lpthread -Wl,--end-group

TARGET = fastrg_cli
SRC = $(wildcard *.c)
OBJ = $(SRC:.c=.o)

GRPCDIR = ../grpc
GRPC_SRC = $(GRPCDIR)/fastrg_grpc_client.cpp
PB_SRC = $(wildcard $(GRPCDIR)/*.cc)
GRPC_OBJ = $(GRPC_SRC:.cpp=.o)
PB_OBJ = $(PB_SRC:.cc=.o)

ifneq ($(shell pkg-config --exists libdpdk && echo 0),0)
$(error "no installation of DPDK found")
endif
	
.PHONY: $(TARGET)
all: $(TARGET)
######################################
# Compile & Link
# 	Must use \tab key after new line
######################################
$(TARGET): $(OBJ) $(GRPC_OBJ) $(PB_OBJ)
	$(CC) $(CFLAGS) $(OBJ) $(GRPC_OBJ) $(PB_OBJ) -o $(TARGET) $(LDFLAGS)

install:
	cp $(TARGET) /usr/local/bin/$(TARGET)

######################################
# Clean 
######################################
clean:
	rm -rf $(OBJ) $(TARGET) .libs
