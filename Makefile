CC = gcc

LIBS = -lm

FLAGS =  -g -O2
CFLAGS = ${FLAGS}

all: arp tour

arp: arp.o api_layer.o get_hw_addrs.o arp_helpers.o
	${CC} ${FLAGS} -o arp arp.o api_layer.o get_hw_addrs.o arp_helpers.o ${LIBS}

tour: tour.o get_hw_addrs.o api_layer.o
	${CC} ${FLAGS} -o tour tour.o get_hw_addrs.o api_layer.o ${LIBS}

tour.o: tour.c
	${CC} ${CFLAGS} -c tour.c

arp.o: arp.c
	${CC} ${CFLAGS} -c arp.c

arp_helpers.o: arp_helpers.c
	${CC} ${CFLAGS} -c arp_helpers.c

api_layer.o: api_layer.c
	${CC} ${CFLAGS} -c api_layer.c

get_hw_addrs.o: get_hw_addrs.c
	${CC} ${FLAGS} -c get_hw_addrs.c

clean:
	rm api_layer.o arp.o arp_helpers.o get_hw_addrs.o tour.o arp tour 
