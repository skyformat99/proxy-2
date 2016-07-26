TEST_COVERAGE=1

ifeq ("$(TEST_COVERAGE)","1")
        COV_FLAG= -coverage
        COV_LIB= -lgcov
endif



CFLAGS= -Wall $(COV_FLAG)

proxy: proxy.o ringbuf.o md5.o rbtree.o smart_list.o
	gcc -o $@ $^ -lev $(COV_LIB)


clean:
	rm -f *.o *.gc* 

c:clean

