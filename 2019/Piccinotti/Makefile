dga: dga.o libCreazioneBigrammi.a libGrafoBigrammi.a
	gcc -o dga dga.o -lpcap -L. -lGrafoBigrammi -lCreazioneBigrammi
	
dga.o: dga.c
	gcc -c dga.c

creazioneBigrammi.o: creazioneBigrammi.c
	gcc -c creazioneBigrammi.c

grafoBigrammi.o: grafoBigrammi.c 
	gcc -c grafoBigrammi.c

libCreazioneBigrammi.a: creazioneBigrammi.o grafoBigrammi.o
	ar r libCreazioneBigrammi.a creazioneBigrammi.o

libGrafoBigrammi.a: grafoBigrammi.o
	ar r libGrafoBigrammi.a grafoBigrammi.o

clean:
	rm dga *.o *.a
	



