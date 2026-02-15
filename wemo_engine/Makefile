LINK = $(CC)

LFLAGS += -pthread -shared

TARGET = libwemoengine.so
STATIC_TARGET = libwemoengine.a

SRCS = $(wildcard *.c)
OBJS = ${SRCS:.c=.o}

LIBS=-lsqlite3
INCLUDES=-I/usr/local/include/upnp -I/usr/include/upnp

.PHONY: all clean

all: $(TARGET) $(STATIC_TARGET)

$(TARGET): $(OBJS)
	$(LINK) $(LFLAGS) -o $(TARGET) $(OBJS) $(LIBS)

$(STATIC_TARGET): $(OBJS)
	ar rcs $(STATIC_TARGET) $(OBJS)

.c.o:
	$(CC) $(CFLAGS) -fPIC $(INCLUDES) -c $< -o $@

clean:

	$(RM) *.o *~ $(TARGET) $(STATIC_TARGET)
