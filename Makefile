all: sbejvt 

sbejvt: sbejvt.cxx pcap.hpp attribute.hpp account.hpp
	gcc -g -Wall sbejvt.cxx -lpcap -lboost_system -lboost_filesystem -lstdc++ -o sbejvt

clean:
	rm -f sbejvt 
