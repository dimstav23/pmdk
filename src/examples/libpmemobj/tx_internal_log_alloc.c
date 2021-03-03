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
#define NUM_THREADS 1
#define LAYOUT_NAME "pool"

#define MAX_BUF_LEN_ROOT 16 /* maximum length of our root buffer */
#define MAX_BUF_LEN_OBJ 256 /* maximum length of our root buffer */
#define NUMBER_OF_OBJECTS_PER_THREAD 20

struct my_root {
    size_t len; /* = strlen(buf) */
    char buf[MAX_BUF_LEN_ROOT];
    PMEMoid first_object;
};

struct my_object {
    size_t len; /* = strlen(buf) */
    char buf[MAX_BUF_LEN_OBJ];
};

struct thread_func_args {
    int tid;
    PMEMobjpool* pop;
};

static void *internal_log_alloc_check(void* args){
    
    PMEMobjpool* pop = ((struct thread_func_args*)args)->pop;
    int tid = ((struct thread_func_args*)args)->tid;
  
    PMEMoid temp[NUMBER_OF_OBJECTS_PER_THREAD];
    TX_BEGIN(pop){   
        for (int i = 0; i < NUMBER_OF_OBJECTS_PER_THREAD ; i++) {
            temp[i] = pmemobj_tx_alloc(sizeof(struct my_object), 0);
            //printf("thread : %d object %d offset : %lx\n", tid, i, temp[i].off);
        }
    } TX_ONCOMMIT{
        printf("transaction #1 commited\n");
    } TX_ONABORT{
		printf("transaction #1 aborted\n");
	} TX_END

    char* obj_data = malloc(MAX_BUF_LEN_OBJ * sizeof(char));
    struct my_object* obj_ptr = NULL;
    TX_BEGIN(pop){   
        for (int i = 0; i < NUMBER_OF_OBJECTS_PER_THREAD ; i++) {
			pmemobj_tx_add_range(temp[i], offsetof(struct my_object, buf), MAX_BUF_LEN_OBJ);
            snprintf(obj_data,MAX_BUF_LEN_OBJ,"Thread %d Data of the Object Number : %d", tid, i);
            obj_ptr = pmemobj_direct(temp[i]);
            pmemobj_memcpy(pop, obj_ptr->buf, obj_data, MAX_BUF_LEN_OBJ, 0);
            printf("Thread %d Data of the Object Number : %d\n", tid, i);
        }
    } TX_ONCOMMIT{
        printf("transaction #2 commited\n");
        free(obj_data);
    } TX_ONABORT{
		printf("transaction #3 aborted\n");
        free(obj_data);
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
            PMEMOBJ_MIN_POOL, CREATE_MODE_RW)) == NULL) {
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

    PMEMoid root = pmemobj_root(pop, sizeof (struct my_root));
    printf("root offset: %"PRIx64"\n", root.off);
    char* root_data = malloc(MAX_BUF_LEN_ROOT * sizeof(char));
    strcpy(root_data, "Root_Obj_");
    struct my_root* my_root = pmemobj_direct(root);
    pmemobj_memcpy_persist(pop, my_root->buf, root_data, MAX_BUF_LEN_ROOT * sizeof(char));
    free(root_data);

    // Create number of threads using normal operations with locks
    pthread_t threads[NUM_THREADS];
    printf("Starting threads with normal operation\n");
    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        struct thread_func_args* packed_args = (struct thread_func_args*)malloc(sizeof(struct thread_func_args));
        packed_args->pop = pop;
        packed_args->tid = i;
        pthread_create(&threads[i], NULL, internal_log_alloc_check, (void *)packed_args);
    }
    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        pthread_join(threads[i], NULL);
    }

    pmemobj_close(pop);

    return 0;
}
