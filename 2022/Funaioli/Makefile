CC = gcc
LDFLAGS = -L /usr/lib/
LIBS = -lrrd -lm

TARGETS = skewness

skewness: skewness.c
	$(CC) $(LDFLAGS) $(LIBS) $< -o $@

clean:
	rm -f skewness
	rm -f skeweddata.rrd skeweddata.png
