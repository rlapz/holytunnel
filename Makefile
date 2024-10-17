TARGET   := holytunnel
IS_DEBUG ?= 0
CC       := cc
CFLAGS   := -std=c11 -Wall -Wextra -pedantic -D_XOPEN_SOURCE=500 -D_POSIX_C_SOURCE=200112L
LFLAGS   := -lcurl
SRC      := main.c holytunnel.c resolver.c picohttpparser.c util.c
OBJ      := $(SRC:.c=.o)


ifeq ($(IS_DEBUG), 1)
	CFLAGS := $(CFLAGS) -g -DDEBUG -O0
	LFLAGS := $(LFLAGS) -fsanitize=address -fsanitize=undefined
else
	CFLAGS := $(CFLAGS) -O2
endif


build: options $(TARGET)

options:
	@echo \'$(TARGET)\' build options:
	@echo "CFLAGS = " $(CFLAGS)
	@echo "CC     = " $(CC)

$(TARGET).o: $(TARGET).c
	@printf "\n%s\n--------------------------\n" "Compiling..."
	$(CC) $(CFLAGS) -c -o $(@) $(<)

$(TARGET): $(OBJ)
	@printf "\n%s\n--------------------------\n" "Linking..."
	$(CC) -o $(@) $(^) $(LFLAGS)

clean:
	@echo cleaning...
	rm -f $(OBJ) $(TARGET)


.PHONY: build clean
