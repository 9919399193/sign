sign_alias = ecc.o entry.o sha256.o

signcheck:$(sign_alias)
	cc -o signcheck $(sign_alias)

ecc.o:ecc.h
entry.o:entry.c
sha256.o:sha256.h

.PHONY:clean
clean:
	-rm signcheck $(sign_alias)