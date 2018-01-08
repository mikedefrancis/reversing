#change the name of the program here
NAME=helloworld

CC=arm-linux-gnueabi-gcc

#add extra c file to compile here
EXTRA_SRC=

#what should be done by default - 1st target
all: $(NAME)

#generate a list of object (.o) files
OBJS=$(patsubst %.c,%.o,$(NAME).c $(EXTRA_SRC))

#main program depend on all objects, rest is done by implicit rules
$(NAME): $(OBJS)
	${CC} ${LDFLAGS} -o ${NAME} ${OBJS} ${LIBS}

#clean up rule
clean:
	rm -f $(NAME) $(OBJS)
	
test: $(NAME)
	./$(NAME)

#all, clean are phony rules, e.g. they should always run
.PHONY: all clean test

# CC      = gcc
# CFLAGS  = -g
# RM      = rm -f
#
#
# default: all
#
# all: hello_world
#
# hello_world: world.c
#     cc -o hello_world world.c
#
# clean veryclean:
#     $(RM) Hello
#

# hello_world: world.c
#       cc -c world.c
# world.o: world.c
#       cc -c world.c
# OBJS=world.o
# BIN=hello_world.bin

# include ../Makefile.include

