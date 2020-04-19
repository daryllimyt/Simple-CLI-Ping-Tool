# Makefile for ping tool

CC=g++
CPPFLAGS = -std=c++11 -W -Wall -Wno-unused-parameter -Wno-reorder -w 


all : clean bin/ping

bin/ping : src/main.cpp
	mkdir -p bin
	$(CC) $(CPPFLAGS) -o bin/ping $<

clean :
	rm -f src/*.o
	rm -f bin/*