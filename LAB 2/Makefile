CC=gcc
CFLAGS= -Wall -Wextra -O2 -lcrypto -Wno-deprecated-declarations -fstack-protector -z noexecstack -D_FORTIFY_SOURCE=2

all: secure_implementation sign_file

secure_implementation: secure_implementation.o
	$(CC) $(CFLAGS)  $< -o $@
sign_file: sign_file.o
	$(CC) $(CFLAGS) $< -o $@
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean clear
clean:
	-rm -v secure_implementation.o sign_file.o
clear: clean
	-rm -v secure_implementation sign_file
