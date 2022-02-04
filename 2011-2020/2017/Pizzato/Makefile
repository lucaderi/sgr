#Autore: Davide Pizzato
#Matricola: 521991
#Gestione di reti 2017
C = gcc
CFLAGS += -Wall -pedantic
DEPS = -lpcap
OUTPUT = results.txt
EXEC = sgrout

#Show help
help:
	@echo "Make help:"
	@echo " install dependencies : make dependencies"
	@echo " compile              : make compile"
	@echo " test                 : make test [i=interface_name]"
	@echo " help                 : make [help]"
	@echo " clean                : make clean"

#Install libpcap
dependencies:
	sudo apt-get install libpcap-dev

#Compile the project
compile:
	$(C) $(CFLAGS) $(DEPS) -o $(EXEC) sgr.c -lpcap

#Execute and save the output in results.txt
test: 
	sudo ./sgrout -i ${i} 

#Remove all the created files
clean:
	rm $(EXEC) $(OUTPUT)