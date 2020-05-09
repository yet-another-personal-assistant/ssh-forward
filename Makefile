CFLAGS += -Wall -Werror -O3
LDFLAGS += -flto
CFLAGS += $(shell pkg-config --cflags libssh)
LDLIBS += $(shell pkg-config --libs libssh)
APP = sshforward

all: $(APP)

$(APP): main.o server.o session.o utils.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

clean:
	-rm -rf *.o $(APP)

IMAGES = image-build image-dev image-deploy
images: $(IMAGES)

image-dev image-deploy: | image-build

image-build: containerfiles/Containerfile.build
	docker build -t sshforward-build -f $^ .
image-dev: containerfiles/Containerfile.dev
	docker build -t sshforward-dev -f $^ .
image-deploy: containerfiles/Containerfile
	docker build -t sshforward -f $^ .

.PHONY: all clean images $(IMAGES)
