KERNEL_ROOT := /usr/src/linux-headers-5.4.0-148-generic

obj-m += hello.o
CC = gcc -Wall

modules:
        @$(MAKE) -C $(KERNEL_ROOT) M=$(shell pwd) modules

clean:
        @$(MAKE) -C $(KERNEL_ROOT) M=$(shell pwd) clean
