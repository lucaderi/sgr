#Whoml makefile per linux
whoml: whoml.o mongoose.o protocolswitch.o flussi.o host.o
	g++ -L/usr/lib/ -L/usr/local/lib/ -L/opt/local/lib -Xlinker -ldl -o "whoml"  mongoose.o protocolswitch.o whoml.o  flussi.o host.o -lpcap -lboost_thread-mt

#whoml.cpp
whoml.o: whoml.cpp ./strutture_dati/host.hpp protocolswitch.hpp ./strutture_dati/flussi.hpp mongoose.h
	g++ -I/opt/local/lib/ -I/opt/local/include/ -O0 -g -Wall -fmessage-length=0 -MMD -MP -c whoml.cpp

#protocolswitch.cpp
protocolswitch.o: protocolswitch.cpp protocolswitch.hpp
	g++ -I/opt/local/include/ -c protocolswitch.cpp

mongoose.o: mongoose.c mongoose.h
	gcc -c mongoose.c

host.o: strutture_dati/host.cpp strutture_dati/host.hpp
	g++ -I/opt/local/include/ -c ./strutture_dati/host.cpp

flussi.o: strutture_dati/flussi.cpp strutture_dati/flussi.hpp
	g++ -I/opt/local/include/ -c ./strutture_dati/flussi.cpp

clean:
	rm *.o whoml