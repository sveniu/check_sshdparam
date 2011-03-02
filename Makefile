target = check_sshdparam

all:
	gcc -lssh2 -o $(target) -W -Wall -g $(target).c

clean:
	rm -f $(target)
