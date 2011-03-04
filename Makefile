target = check_sshdparam

all:
	gcc -lssh2 -o $(target) -W -Wall -g $(target).c

static:
	gcc $(target).c -static /usr/lib/libssh2.a -static /usr/lib/libgcrypt.a -static /usr/lib/libgpg-error.a -static /usr/lib/libz.a -o $(target) -W -Wall -g 


clean:
	rm -f $(target)
