LINK = $(CC)

CFLAGS += -Wall
LDFLAGS += -pthread

TARGET = wemo_client

SRCS = $(wildcard *.c)
OBJS = ${SRCS:.c=.o}

UPNP_BASE ?= ../../libupnp-1.14.0
IXML_LIB_DIR := $(abspath $(UPNP_BASE)/ixml/.libs)
IXML_INC_DIR := $(abspath $(UPNP_BASE)/ixml/inc)
ENGINE_LIB_DIR := $(abspath ../wemo_engine)
RPATH_FLAGS := -Wl,-rpath,$(ENGINE_LIB_DIR) -Wl,-rpath,$(IXML_LIB_DIR)

LIBS = -lsqlite3 -lwemoengine -lixml -lcrypto -L../wemo_engine -L$(IXML_LIB_DIR) -L/usr/local/lib

ifeq ($(STATIC_ENGINE),1)
LIBS = -lsqlite3 ../wemo_engine/libwemoengine.a -lixml -lcrypto -L$(IXML_LIB_DIR) -L/usr/local/lib
endif
INCLUDES = -I../wemo_engine -I$(IXML_INC_DIR) -I/usr/local/include -I/usr/include

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(LINK) $(LDFLAGS) $(RPATH_FLAGS) -o $(TARGET) $(OBJS) $(LIBS)

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:

	$(RM) *.o *~ $(TARGET)
