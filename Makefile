CFLAGS += -Wall -Werror -O3
CFLAGS += $(shell pkg-config --cflags libssh)
LDLIBS += $(shell pkg-config --libs libssh)
APP = sshforward

all: $(APP)

$(APP): main.o server.o session.o utils.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

clean:
	-rm -rf *.o $(APP)

.PHONY: all clean
