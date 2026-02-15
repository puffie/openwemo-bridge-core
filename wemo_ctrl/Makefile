LINK = $(CC)

LFLAGS += -pthread
CFLAGS += -g

TARGET = wemo_ctrl

SRCS = $(wildcard *.c)
OBJS = ${SRCS:.c=.o}

UPNP_BASE ?= ../../libupnp-1.14.0
UPNP_LIB_DIR := $(abspath $(UPNP_BASE)/upnp/.libs)
IXML_LIB_DIR := $(abspath $(UPNP_BASE)/ixml/.libs)
UPNP_INC_DIR := $(abspath $(UPNP_BASE)/upnp/inc)
IXML_INC_DIR := $(abspath $(UPNP_BASE)/ixml/inc)
RPATH_FLAGS := -Wl,-rpath,$(UPNP_LIB_DIR) -Wl,-rpath,$(IXML_LIB_DIR)

LIBS = -lupnp -lsqlite3 -lixml -L$(UPNP_LIB_DIR) -L$(IXML_LIB_DIR) -L/usr/local/lib

ifeq ($(STATIC_ENGINE),1)
LIBS = -lupnp -lsqlite3 -lixml ../wemo_engine/libwemoengine.a -L$(UPNP_LIB_DIR) -L$(IXML_LIB_DIR) -L/usr/local/lib
endif

INCLUDES = -I../wemo_engine -I$(UPNP_INC_DIR) -I$(IXML_INC_DIR) -I/usr/local/include/upnp -I/usr/include/upnp

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(LINK) $(LDFLAGS) $(LFLAGS) $(RPATH_FLAGS) -o $(TARGET) $(OBJS) $(LIBS)

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:

	$(RM) *.o *~ $(TARGET)
