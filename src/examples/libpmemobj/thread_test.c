#include <ex_common.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/stat.h>
#include <libpmemobj.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include <pthread.h>
#define NUM_THREADS 2
#define LAYOUT_NAME "pool"

#define MAX_BUF_LEN_ROOT 16 /* maximum length of our root buffer */
#define MAX_BUF_LEN_OBJ 256 /* maximum length of our root buffer */
#define NUMBER_OF_OBJECTS_PER_THREAD 50

struct my_root {
    size_t len; /* = strlen(buf) */
    char buf[MAX_BUF_LEN_ROOT];
    PMEMoid first_object;
};

struct my_object {
    size_t len; /* = strlen(buf) */
    char buf[MAX_BUF_LEN_OBJ];
    PMEMoid next_object;
};

struct thread_func_args {
    int tid;
    PMEMobjpool* pop;
};

static void *alloc_objects_tx(void* args){
    
    PMEMobjpool* pop = ((struct thread_func_args*)args)->pop;
    int  __attribute__((unused)) tid = ((struct thread_func_args*)args)->tid;
    int errnum __attribute__((unused)) = 2;
    //char* obj_data = malloc(MAX_BUF_LEN_OBJ * sizeof(char));
    
    PMEMoid  __attribute__((unused)) temp[NUMBER_OF_OBJECTS_PER_THREAD];
    TX_BEGIN(pop){
        
        for (int i = 0; i < NUMBER_OF_OBJECTS_PER_THREAD ; i++) {
			//snprintf(obj_data,MAX_BUF_LEN_OBJ,"Thread %d Data of the Object Number : %d", *threadid, i);
            temp[i] = pmemobj_tx_zalloc(sizeof(struct my_object), 0);
            //printf("thread : %d object %d offset : %lx\n", tid, i, temp[i].off);
        }

        if (tid == 1 || tid == 2)
            pmemobj_tx_abort(errnum);
        
    } TX_ONCOMMIT{
        printf("transaction commited\n");
    } TX_ONABORT{
		printf("transaction aborted\n");
	} TX_END

    free(args);
    return NULL;
}

int main(int argc, char const *argv[])
{

    PMEMobjpool* pop;
    const char *path = "/dev/shm/arraypool_vanilla";
    //int errnum = 2;

    if (file_exists(path) != 0) {
        if ((pop = pmemobj_create(path, LAYOUT_NAME,
            100 * PMEMOBJ_MIN_POOL, CREATE_MODE_RW)) == NULL) {
            printf("failed to create pool\n");
            return 1;
        }
    } 
    else {
        if ((pop = pmemobj_open(path, LAYOUT_NAME))
            == NULL) {
            printf("failed to open pers pool\n");
            return 1;
        }
    }

   /*
    PMEMoid root = pmemobj_root(pop, sizeof (struct my_root));
    printf("root offset: %"PRIx64"\n", root.off);
    char* root_data = malloc(MAX_BUF_LEN_ROOT * sizeof(char));
    strcpy(root_data, "Root_Obj_");
    struct my_root* my_root = pmemobj_direct(root);
    pmemobj_memcpy_persist(pop, my_root->buf, root_data, MAX_BUF_LEN_ROOT * sizeof(char));
    free(root_data);
   */
    printf ("pool create/open ended\n");

    // Create number of threads using normal operations with locks
    pthread_t threads[NUM_THREADS];
    printf("Starting threads with normal operation\n");
    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        struct thread_func_args* packed_args = (struct thread_func_args*)malloc(sizeof(struct thread_func_args));
        packed_args->pop = pop;
        packed_args->tid = i;
        pthread_create(&threads[i], NULL, alloc_objects_tx, (void *)packed_args);
    }
    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        pthread_join(threads[i], NULL);
    }

    pmemobj_close(pop);

    /*


    // Create number of threads using transactions without locks
    printf("Starting threads with transactions\n");
    pthread_t tx_threads[NUM_THREADS];
    *rootp = 0;
    pmemobj_persist(pop, rootp, sizeof(*rootp));
    clock_t beginTX = clock();
    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        pthread_create(&tx_threads[i], NULL, incrementTX, NULL);
    }

    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        pthread_join(tx_threads[i], NULL);
    }
    clock_t endTX = clock();
    printf("Finished transaction threads\n");
    printf("%d\n", *rootp);

    double durationNormal = (double)(endNormal-beginNormal)/CLOCKS_PER_SEC;
    double durationTX = (double)(endTX-beginTX)/CLOCKS_PER_SEC;

    printf("Runtime of the normal operations: %.17g\n", durationNormal);
    printf("Runtime of the TX operations: %.17g\n", durationTX);

    pthread_exit(NULL);
    */
    return 0;
}
