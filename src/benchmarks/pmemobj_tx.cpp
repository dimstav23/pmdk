/*
 * Copyright 2015-2018, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *      * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 *      * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *
 *      * Neither the name of the copyright holder nor the names of its
 *        contributors may be used to endorse or promote products derived
 *        from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * pmemobj_tx.cpp -- pmemobj_tx_alloc(), pmemobj_tx_free(),
 * pmemobj_tx_realloc(), pmemobj_tx_add_range() benchmarks.
 */
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

#include "benchmark.hpp"
#include "file.h"
#include "libpmemobj.h"
#include "poolset_util.hpp"

#define LAYOUT_NAME "benchmark"
#define FACTOR 1.2f
#define ALLOC_OVERHEAD 64
/*
 * operations number is limited to prevent stack overflow during
 * performing recursive functions.
 */
#define MAX_OPS 10000

TOID_DECLARE(struct item, 0);

struct obj_tx_bench;
struct obj_tx_worker;

int obj_tx_init(struct benchmark *bench, struct benchmark_args *args);
int obj_tx_exit(struct benchmark *bench, struct benchmark_args *args);


/*
 * type_pmdk_func_mode -- type PMDK func mode
 */
enum type_pmdk_func_mode {
	PMDK_READ,
	PMDK_WRITE,
	PMDK_READ_AND_WRITE,
	PMDK_PUT,
	PMDK_GET,
	PMDK_UPDATE,
	PMDK_DELETE,
	PMDK_GET_PUT,
	PMDK_UNKNOWN
};

/*
 * type_num_mode -- type number mode
 */
enum type_num_mode {
	NUM_MODE_ONE,
	NUM_MODE_PER_THREAD,
	NUM_MODE_RAND,
	NUM_MODE_UNKNOWN
};

/*
 * op_mode -- operation type
 */
enum op_mode {
	OP_MODE_COMMIT,
	OP_MODE_ABORT,
	OP_MODE_ABORT_NESTED,
	OP_MODE_ONE_OBJ,
	OP_MODE_ONE_OBJ_NESTED,
	OP_MODE_ONE_OBJ_RANGE,
	OP_MODE_ONE_OBJ_NESTED_RANGE,
	OP_MODE_ALL_OBJ,
	OP_MODE_ALL_OBJ_NESTED,
	OP_MODE_UNKNOWN
};

/*
 * lib_mode -- operation type
 */
enum lib_mode {
	LIB_MODE_DRAM,
	LIB_MODE_OBJ_TX,
	LIB_MODE_OBJ_ATOMIC,
	LIB_MODE_NONE,
};

/*
 * nesting_mode -- nesting type
 */
enum nesting_mode {
	NESTING_MODE_SIM,
	NESTING_MODE_TX,
	NESTING_MODE_UNKNOWN,
};

/*
 * add_range_mode -- operation type for obj_add_range benchmark
 */
enum add_range_mode { ADD_RANGE_MODE_ONE_TX, ADD_RANGE_MODE_NESTED_TX };

/*
 * parse_mode -- parsing function type
 */
enum parse_mode { PARSE_OP_MODE, PARSE_OP_MODE_ADD_RANGE };

typedef size_t (*fn_type_num_t)(struct obj_tx_bench *obj_bench,
				size_t worker_idx, size_t op_idx);

typedef size_t (*fn_num_t)(size_t idx);

typedef int (*fn_op_t)(struct obj_tx_bench *obj_bench,
		       struct worker_info *worker, size_t idx);

typedef struct offset (*fn_os_off_t)(struct obj_tx_bench *obj_bench,
				     size_t idx);

typedef enum op_mode (*fn_parse_t)(const char *arg);

/*
 * obj_tx_args -- stores command line parsed arguments.
 */
struct obj_tx_args {

	/*
	 * operation which will be performed when flag io set to false.
	 *	modes for obj_tx_alloc, obj_tx_free and obj_tx_realloc:
	 *		- basic - transaction will be committed
	 *		- abort - 'external' transaction will be aborted.
	 *		- abort-nested - all nested transactions will be
	 *		  aborted.
	 *
	 *	modes for  obj_tx_add_range benchmark:
	 *		- basic - one object is added to undo log many times in
	 *		  one transaction.
	 *		- range - fields of one object are added to undo
	 *		  log many times in one transaction.
	 *		- all-obj - all objects are added to undo log in
	 *		  one transaction.
	 *		- range-nested - fields of one object are added to undo
	 *		  log many times in many nested transactions.
	 *		- one-obj-nested - one object is added to undo log many
	 *		  times in many nested transactions.
	 *		- all-obj-nested - all objects are added to undo log in
	 *		  many separate, nested transactions.
	 */
	char *operation;

	/*
	 * type number for each persistent object. There are three modes:
	 *		- one - all of objects have the same type number
	 *		- per-thread - all of object allocated by the same
	 *		  thread have the same type number
	 *		- rand - type numbers are assigned randomly for
	 *		  each persistent object
	 */
	char *type_num;

	/*
	 * define s which library will be used in main operations There are
	 * three modes in which benchmark can be run:
	 *		- tx - uses PMEM transactions
	 *		- pmem - uses PMEM without transactions
	 *		- dram - does not use PMEM
	 */
	char *lib;
	char *pmdk_func; 	/* type of pmdk func */
	int get_ratio; 		/* read percentage */
	int tx_ops; 		/* operations per transaction */
	unsigned nested;    /* number of nested transactions */
	unsigned min_size;  /* minimum allocation size */
	unsigned min_rsize; /* minimum reallocation size */
	unsigned rsize;     /* reallocation size */
	bool change_type;   /* change type number in reallocation */
	size_t obj_size;    /* size of each allocated object */
	size_t n_ops;       /* number of operations */
	int parse_mode;     /* type of parsing function */
};

/*
 * obj_tx_bench -- stores variables used in benchmark, passed within functions.
 */
static struct obj_tx_bench {
	PMEMobjpool *pop;	     /* handle to persistent pool */
	struct obj_tx_args *obj_args; /* pointer to benchmark arguments */
	size_t *random_types;	 /* array to store random type numbers */
	size_t *sizes;      /* array to store size of each allocation */
	size_t *resizes;    /* array to store size of each reallocation */
	size_t n_objs;      /* number of objects to allocate */
	int type_mode;      /* type number mode */
	int op_mode;		/* type of operation */
	int lib_mode;       /* type of operation used in initialization */
	int lib_op;	 		/* type of main operation */
	int pmdk_func; 		/* type of pmdk func */
	int lib_op_free;    /* type of main operation */
	int nesting_mode;   /* type of nesting in main operation */
	fn_num_t n_oid;     /* returns object's number in array */
	fn_os_off_t fn_off; /* returns offset for proper operation */

	/*
	 * fn_type_num gets proper function assigned, depending on the
	 * value of the type_mode argument, which returns proper type number for
	 * each persistent object. Possible functions are:
	 *	- type_mode_one,
	 *	- type_mode_rand.
	 */
	fn_type_num_t fn_type_num;

	/*
	 * fn_op gets proper array with functions pointer assigned, depending on
	 * function which is tested by benchmark. Possible arrays are:
	 *	-alloc_op
	 *	-free_op
	 *	-realloc_op
	 */
	fn_op_t *fn_op;
} obj_bench;

/*
 * item -- TOID's structure
 */
struct item;

/*
 * obj_tx_worker - stores variables used by one thread.
 */
struct obj_tx_worker {
	TOID(struct item) * oids;
	char **items;
	unsigned tx_level;
	unsigned max_level;
};

/*
 * offset - stores offset data used in pmemobj_tx_add_range()
 */
struct offset {
	uint64_t off;
	size_t size;
};

/*
 * alloc_dram -- main operations for obj_tx_alloc benchmark in dram mode
 */
static int
alloc_dram(struct obj_tx_bench *obj_bench, struct worker_info *worker,
	   size_t idx)
{
	auto *obj_worker = (struct obj_tx_worker *)worker->priv;
	obj_worker->items[idx] = (char *)malloc(obj_bench->sizes[idx]);
	if (obj_worker->items[idx] == nullptr) {
		perror("malloc");
		return -1;
	}
	return 0;
}

/*
 * alloc_pmem -- main operations for obj_tx_alloc benchmark in pmem mode
 */
static int
alloc_pmem(struct obj_tx_bench *obj_bench, struct worker_info *worker,
	   size_t idx)
{
	size_t type_num = obj_bench->fn_type_num(obj_bench, worker->index, idx);
	auto *obj_worker = (struct obj_tx_worker *)worker->priv;
	if (pmemobj_alloc(obj_bench->pop, &obj_worker->oids[idx].oid,
			  obj_bench->sizes[idx], type_num, nullptr,
			  nullptr) != 0) {
		perror("pmemobj_alloc");
		return -1;
	}
	return 0;
}

/*
 * alloc_tx -- main operations for obj_tx_alloc benchmark in tx mode
 */
static int
alloc_tx(struct obj_tx_bench *obj_bench, struct worker_info *worker, size_t idx)
{
	size_t type_num = obj_bench->fn_type_num(obj_bench, worker->index, idx);
	auto *obj_worker = (struct obj_tx_worker *)worker->priv;
	//obj_worker->oids[idx].oid = pmemobj_tx_xalloc(
	//	obj_bench->sizes[idx], type_num, POBJ_XALLOC_NO_FLUSH);
	obj_worker->oids[idx].oid = pmemobj_tx_zalloc(
		obj_bench->sizes[idx], type_num);
	if (OID_IS_NULL(obj_worker->oids[idx].oid)) {
		perror("pmemobj_tx_alloc");
		return -1;
	}
	return 0;
}

/*
 * free_dram -- main operations for obj_tx_free benchmark in dram mode
 */
static int
free_dram(struct obj_tx_bench *obj_bench, struct worker_info *worker,
	  size_t idx)
{
	auto *obj_worker = (struct obj_tx_worker *)worker->priv;
	free(obj_worker->items[idx]);
	return 0;
}

/*
 * free_pmem -- main operations for obj_tx_free benchmark in pmem mode
 */
static int
free_pmem(struct obj_tx_bench *obj_bench, struct worker_info *worker,
	  size_t idx)
{
	auto *obj_worker = (struct obj_tx_worker *)worker->priv;
	POBJ_FREE(&obj_worker->oids[idx]);
	return 0;
}

/*
 * free_tx -- main operations for obj_tx_free benchmark in tx mode
 */
static int
free_tx(struct obj_tx_bench *obj_bench, struct worker_info *worker, size_t idx)
{
	auto *obj_worker = (struct obj_tx_worker *)worker->priv;
	TX_FREE(obj_worker->oids[idx]);
	return 0;
}

/*
 * no_free -- exit operation for benchmarks obj_tx_alloc and obj_tx_free
 * if there is no need to free memory
 */
static int
no_free(struct obj_tx_bench *obj_bench, struct worker_info *worker, size_t idx)
{
	return 0;
}

/*
 * realloc_dram -- main operations for obj_tx_realloc benchmark in dram mode
 */
static int
realloc_dram(struct obj_tx_bench *obj_bench, struct worker_info *worker,
	     size_t idx)
{
	auto *obj_worker = (struct obj_tx_worker *)worker->priv;
	auto *tmp = (char *)realloc(obj_worker->items[idx],
				    obj_bench->resizes[idx]);
	if (tmp == nullptr) {
		perror("realloc");
		return -1;
	}
	obj_worker->items[idx] = tmp;
	return 0;
}

/*
 * realloc_pmem -- main operations for obj_tx_realloc benchmark in pmem mode
 */
static int
realloc_pmem(struct obj_tx_bench *obj_bench, struct worker_info *worker,
	     size_t idx)
{
	auto *obj_worker = (struct obj_tx_worker *)worker->priv;
	size_t type_num = obj_bench->fn_type_num(obj_bench, worker->index, idx);
	if (obj_bench->obj_args->change_type)
		type_num++;
	if (pmemobj_realloc(obj_bench->pop, &obj_worker->oids[idx].oid,
			    obj_bench->resizes[idx], type_num) != 0) {
		perror("pmemobj_realloc");
		return -1;
	}
	return 0;
}

/*
 * realloc_tx -- main operations for obj_tx_realloc benchmark in tx mode
 */
static int
realloc_tx(struct obj_tx_bench *obj_bench, struct worker_info *worker,
	   size_t idx)
{
	auto *obj_worker = (struct obj_tx_worker *)worker->priv;
	size_t type_num = obj_bench->fn_type_num(obj_bench, worker->index, idx);
	if (obj_bench->obj_args->change_type)
		type_num++;
	obj_worker->oids[idx].oid = pmemobj_tx_realloc(
		obj_worker->oids[idx].oid, obj_bench->sizes[idx], type_num);
	if (OID_IS_NULL(obj_worker->oids[idx].oid)) {
		perror("pmemobj_tx_realloc");
		return -1;
	}
	return 0;
}

/*
 * add_range_nested_tx -- main operations of the obj_tx_add_range with nesting.
 */
static int
add_range_nested_tx(struct obj_tx_bench *obj_bench, struct worker_info *worker,
		    size_t idx)
{
	int ret = 0;
	auto *obj_worker = (struct obj_tx_worker *)worker->priv;
	TX_BEGIN(obj_bench->pop)
	{
		if (obj_bench->obj_args->n_ops != obj_worker->tx_level) {
			size_t n_oid = obj_bench->n_oid(obj_worker->tx_level);
			struct offset offset = obj_bench->fn_off(
				obj_bench, obj_worker->tx_level);
			pmemobj_tx_add_range(obj_worker->oids[n_oid].oid,
					     offset.off, offset.size);
			obj_worker->tx_level++;
			ret = add_range_nested_tx(obj_bench, worker, idx);
		}
	}
	TX_ONABORT
	{
		fprintf(stderr, "transaction failed\n");
		ret = -1;
	}
	TX_END
	return ret;
}

/*
 * add_range_tx -- main operations of the obj_tx_add_range without nesting.
 */
static int
add_range_tx(struct obj_tx_bench *obj_bench, struct worker_info *worker,
	     size_t idx)
{
	int ret = 0;
	size_t i = 0;
	auto *obj_worker = (struct obj_tx_worker *)worker->priv;
	TX_BEGIN(obj_bench->pop)
	{
		for (i = 0; i < obj_bench->obj_args->n_ops; i++) {
			size_t n_oid = obj_bench->n_oid(i);
			struct offset offset = obj_bench->fn_off(obj_bench, i);
			ret = pmemobj_tx_add_range(obj_worker->oids[n_oid].oid,
						   offset.off, offset.size);
		}
	}
	TX_ONABORT
	{
		fprintf(stderr, "transaction failed\n");
		ret = -1;
	}
	TX_END
	return ret;
}

/*
 * pmdk_read -- 
 */
static int
pmdk_read(struct obj_tx_bench *obj_bench, struct worker_info *worker, size_t idx)
{
	int ret = 0;
	size_t type_num = obj_bench->fn_type_num(obj_bench, worker->index, idx);
	auto *obj_worker = (struct obj_tx_worker *)worker->priv;
	void* object_data __attribute__((unused)) = NULL;
	TX_BEGIN(obj_bench->pop)
	{
		obj_worker->oids[idx].oid = pmemobj_tx_zalloc(obj_bench->sizes[idx], type_num);//, POBJ_XALLOC_NO_FLUSH
		if (OID_IS_NULL(obj_worker->oids[idx].oid)) {
			perror("pmdk_pmemobj_tx_alloc");
			return -1;
		}
		object_data = pmemobj_direct(obj_worker->oids[idx].oid);
	}
	TX_ONABORT
	{
		fprintf(stderr, "transaction failed\n");
		ret = -1;
	}
	TX_END
	return ret;
}

/*
 * pmdk_write -- 
 */
static int
pmdk_write(struct obj_tx_bench *obj_bench, struct worker_info *worker, size_t idx)
{
	int ret = 0;
	size_t type_num = obj_bench->fn_type_num(obj_bench, worker->index, idx);
	auto *obj_worker = (struct obj_tx_worker *)worker->priv;
	uint8_t* buffer =(uint8_t*)malloc(obj_bench->sizes[idx]*sizeof(uint8_t));
	TX_BEGIN(obj_bench->pop)
	{
		obj_worker->oids[idx].oid = pmemobj_tx_zalloc(obj_bench->sizes[idx], type_num);//, POBJ_XALLOC_NO_FLUSH
		if (OID_IS_NULL(obj_worker->oids[idx].oid)) {
			perror("pmdk_pmemobj_tx_alloc");
			return -1;
		}
		pmemobj_tx_add_range(obj_worker->oids[idx].oid, 0, obj_bench->sizes[idx]);
		void* pmem_ptr = pmemobj_direct(obj_worker->oids[idx].oid);
		pmemobj_memcpy(obj_bench->pop, pmem_ptr, buffer, obj_bench->sizes[idx], 0);
		//pmemobj_memcpy_persist(obj_bench->pop, pmem_ptr, buffer, obj_bench->sizes[idx]);
		free(buffer);
	}
	TX_ONABORT
	{
		free(buffer);
		fprintf(stderr, "transaction failed\n");
		ret = -1;
	}
	TX_END
	return ret;
}

/*
 * pmdk_read_and_write -- 
 */
static int
pmdk_read_and_write(struct obj_tx_bench *obj_bench, struct worker_info *worker, size_t idx)
{
	int ret = 0;
	size_t type_num = obj_bench->fn_type_num(obj_bench, worker->index, idx);
	auto *obj_worker = (struct obj_tx_worker *)worker->priv;
	uint8_t* buffer =(uint8_t*)malloc(obj_bench->sizes[idx]*sizeof(uint8_t));
	TX_BEGIN(obj_bench->pop)
	{
		obj_worker->oids[idx].oid = pmemobj_tx_zalloc(obj_bench->sizes[idx], type_num);//, POBJ_XALLOC_NO_FLUSH
		if (OID_IS_NULL(obj_worker->oids[idx].oid)) {
			perror("pmdk_pmemobj_tx_alloc");
			return -1;
		}
		pmemobj_tx_add_range(obj_worker->oids[idx].oid, 0, obj_bench->sizes[idx]);
		void* pmem_ptr = pmemobj_direct(obj_worker->oids[idx].oid);
		pmemobj_memcpy(obj_bench->pop, pmem_ptr, buffer, obj_bench->sizes[idx], 0);
		pmem_ptr = pmemobj_direct(obj_worker->oids[idx].oid);
		//pmemobj_memcpy_persist(obj_bench->pop, pmem_ptr, buffer, obj_bench->sizes[idx]);
		free(buffer);
	}
	TX_ONABORT
	{
		free(buffer);
		fprintf(stderr, "transaction failed\n");
		ret = -1;
	}
	TX_END
	return ret;
}

/*
 * pmdk_put -- 
 */
static int
pmdk_put(struct obj_tx_bench *obj_bench, struct worker_info *worker, size_t idx)
{
	int ret = 0;
	size_t type_num = obj_bench->fn_type_num(obj_bench, worker->index, idx);
	auto *obj_worker = (struct obj_tx_worker *)worker->priv;
	//char const *data_to_write = "brand new data\n";
	TX_BEGIN(obj_bench->pop)
	{
		obj_worker->oids[idx].oid = pmemobj_tx_zalloc(obj_bench->sizes[idx], type_num);//, POBJ_XALLOC_NO_FLUSH
		if (OID_IS_NULL(obj_worker->oids[idx].oid)) {
			perror("pmdk_pmemobj_tx_alloc");
			return -1;
		}
		//sobj_tx_add_range(obj_worker->oids[idx].oid, 0, obj_bench->sizes[idx]);
		//sobj_tx_write(obj_bench->pop, obj_worker->oids[idx].oid, (void*)data_to_write);
		//sobj_tx_read(obj_bench->pop, obj_worker->oids[idx].oid);
	}
	TX_ONABORT
	{
		fprintf(stderr, "transaction failed\n");
		ret = -1;
	}
	TX_END
	return ret;
}

/*
 * pmdk_get -- 
 */
static int
pmdk_get(struct obj_tx_bench *obj_bench, struct worker_info *worker, size_t idx)
{
	void* ret = NULL;
	auto *obj_worker = (struct obj_tx_worker *)worker->priv;
	TX_BEGIN(obj_bench->pop)
	{
		ret = pmemobj_direct(obj_worker->oids[idx].oid);
	}
	TX_ONABORT
	{
		fprintf(stderr, "transaction failed\n");
		ret = NULL;
	}
	TX_END

	return(ret==NULL);
}

/*
 * pmdk_update -- 
 */
static int
pmdk_update(struct obj_tx_bench *obj_bench, struct worker_info *worker, size_t idx)
{
	int ret = 0;
	auto *obj_worker = (struct obj_tx_worker *)worker->priv;
	uint8_t* buffer =(uint8_t*)malloc(obj_bench->sizes[idx]*sizeof(uint8_t));
	TX_BEGIN(obj_bench->pop)
	{
		pmemobj_tx_add_range(obj_worker->oids[idx].oid, 0, obj_bench->sizes[idx]);
		void* pmem_ptr = pmemobj_direct(obj_worker->oids[idx].oid);
		pmemobj_memcpy(obj_bench->pop, pmem_ptr, buffer, obj_bench->sizes[idx], 0);
		//pmemobj_memcpy_persist(obj_bench->pop, pmem_ptr, buffer, obj_bench->sizes[idx]);
		free(buffer);
	}
	TX_ONABORT
	{
		free(buffer);
		fprintf(stderr, "transaction failed\n");
		ret = -1;
	}
	TX_END

	return ret;
}

/*
 * pmdk_delete -- 
 */
static int
pmdk_delete(struct obj_tx_bench *obj_bench, struct worker_info *worker, size_t idx)
{
	int ret = 0;
	auto *obj_worker = (struct obj_tx_worker *)worker->priv;
	TX_BEGIN(obj_bench->pop)
	{
		ret = pmemobj_tx_free(obj_worker->oids[idx].oid);
	}
	TX_ONABORT
	{
		fprintf(stderr, "transaction failed\n");
		ret = -1;
	}
	TX_END

	return ret;
}

/*
static void* test_tx_read(PMEMoid oid) {
	void* pmem_pointer = pmemobj_direct(oid);
    assert(pmem_pointer!=NULL);
    int actual_size = 4096;
    uint8_t* decryptedtext = (uint8_t*)malloc(sizeof(uint8_t)* actual_size);
    memcpy(decryptedtext, pmem_pointer, actual_size);
    return decryptedtext;
}
*/
/*
 * pmdk_get_put -- 
 */
static int
pmdk_get_put(struct obj_tx_bench *obj_bench, struct worker_info *worker, size_t idx)
{
	int ret = 0;
	void* ret_obj = NULL;
	auto *obj_worker = (struct obj_tx_worker *)worker->priv;
	uint8_t* buffer = NULL;
	unsigned int seedp = 0;

	/*
	for (int i = 0; i < obj_bench->obj_args->tx_ops; i++) {
			if (rand_r(&seedp)%100 < obj_bench->obj_args->get_ratio) {
				ret_obj = sobj_tx_read(obj_bench->pop, obj_worker->oids[(idx+i)%obj_bench->n_objs].oid, obj_bench->sizes[idx]);
				assert(ret_obj!=NULL);
				free(ret_obj);
			}
			else {
				buffer = (uint8_t*)calloc(obj_bench->sizes[(idx+i)%obj_bench->n_objs], sizeof(uint8_t));
				
				sobj_tx_write(obj_bench->pop, obj_worker->oids[(idx+i)%obj_bench->n_objs].oid, 
								obj_bench->sizes[(idx+i)%obj_bench->n_objs], buffer);
				free(buffer);
			}
	}
	*/
	
	TX_BEGIN(obj_bench->pop)
	{
		for (int i = 0; i < obj_bench->obj_args->tx_ops; i++) {
			if (rand_r(&seedp)%100 < obj_bench->obj_args->get_ratio) {
				ret_obj = sobj_tx_read(obj_bench->pop, obj_worker->oids[(idx+i)%obj_bench->n_objs].oid, obj_bench->sizes[idx]);
				assert(ret_obj!=NULL);
				free(ret_obj);
			}
			else {
				buffer = (uint8_t*)calloc(obj_bench->sizes[(idx+i)%obj_bench->n_objs], sizeof(uint8_t));
				
				sobj_tx_write(obj_bench->pop, obj_worker->oids[(idx+i)%obj_bench->n_objs].oid, 
								obj_bench->sizes[(idx+i)%obj_bench->n_objs], buffer);
				free(buffer);
			}
		}
	}
	TX_ONABORT
	{
		free(buffer);
		fprintf(stderr, "transaction failed\n");
		ret = -1;
	}
	TX_END
	
	return(ret);
}

/*
 * obj_op_sim -- main function for benchmarks which simulates nested
 * transactions on dram or pmemobj atomic API by calling function recursively.
 */
static int
obj_op_sim(struct obj_tx_bench *obj_bench, struct worker_info *worker,
	   size_t idx)
{
	int ret = 0;
	auto *obj_worker = (struct obj_tx_worker *)worker->priv;
	if (obj_worker->max_level == obj_worker->tx_level) {
		ret = obj_bench->fn_op[obj_bench->lib_op](obj_bench, worker,
							  idx);
	} else {
		obj_worker->tx_level++;
		ret = obj_op_sim(obj_bench, worker, idx);
	}
	return ret;
}

/*
 * obj_op_tx -- main recursive function for transactional benchmarks
 */
static int
obj_op_tx(struct obj_tx_bench *obj_bench, struct worker_info *worker,
	  size_t idx)
{
	volatile int ret = 0;
	auto *obj_worker = (struct obj_tx_worker *)worker->priv;
	TX_BEGIN(obj_bench->pop)
	{
		if (obj_worker->max_level == obj_worker->tx_level) {
			ret = obj_bench->fn_op[obj_bench->lib_op](obj_bench,
								  worker, idx);
			if (obj_bench->op_mode == OP_MODE_ABORT_NESTED)
				pmemobj_tx_abort(-1);
		} else {
			obj_worker->tx_level++;
			ret = obj_op_tx(obj_bench, worker, idx);
			if (--obj_worker->tx_level == 0 &&
			    obj_bench->op_mode == OP_MODE_ABORT)
				pmemobj_tx_abort(-1);
		}
	}
	TX_ONABORT
	{
		if (obj_bench->op_mode != OP_MODE_ABORT &&
		    obj_bench->op_mode != OP_MODE_ABORT_NESTED) {
			fprintf(stderr, "transaction failed\n");
			ret = -1;
		}
	}
	TX_END
	return ret;
}

/*
 * type_mode_one -- always returns 0, as in the mode NUM_MODE_ONE
 * all of the persistent objects have the same type_number value.
 */
static size_t
type_mode_one(struct obj_tx_bench *obj_bench, size_t worker_idx, size_t op_idx)
{
	return 0;
}

/*
 * type_mode_per_thread -- always returns worker index to all of the persistent
 * object allocated by the same thread have the same type number.
 */
static size_t
type_mode_per_thread(struct obj_tx_bench *obj_bench, size_t worker_idx,
		     size_t op_idx)
{
	return worker_idx;
}

/*
 * type_mode_rand -- returns the value from the random_types array assigned
 * for the specific operation in a specific thread.
 */
static size_t
type_mode_rand(struct obj_tx_bench *obj_bench, size_t worker_idx, size_t op_idx)
{
	return obj_bench->random_types[op_idx];
}

/*
 * parse_op_mode_add_range -- parses command line "--operation" argument
 * and returns proper op_mode enum value for obj_tx_add_range.
 */
static enum op_mode
parse_op_mode_add_range(const char *arg)
{
	if (strcmp(arg, "basic") == 0)
		return OP_MODE_ONE_OBJ;
	else if (strcmp(arg, "one-obj-nested") == 0)
		return OP_MODE_ONE_OBJ_NESTED;
	else if (strcmp(arg, "range") == 0)
		return OP_MODE_ONE_OBJ_RANGE;
	else if (strcmp(arg, "range-nested") == 0)
		return OP_MODE_ONE_OBJ_NESTED_RANGE;
	else if (strcmp(arg, "all-obj") == 0)
		return OP_MODE_ALL_OBJ;
	else if (strcmp(arg, "all-obj-nested") == 0)
		return OP_MODE_ALL_OBJ_NESTED;
	else
		return OP_MODE_UNKNOWN;
}

/*
 * parse_op_mode -- parses command line "--operation" argument
 * and returns proper op_mode enum value.
 */
static enum op_mode
parse_op_mode(const char *arg)
{
	if (strcmp(arg, "basic") == 0)
		return OP_MODE_COMMIT;
	else if (strcmp(arg, "abort") == 0)
		return OP_MODE_ABORT;
	else if (strcmp(arg, "abort-nested") == 0)
		return OP_MODE_ABORT_NESTED;
	else
		return OP_MODE_UNKNOWN;
}

static fn_op_t alloc_op[] = {alloc_dram, alloc_tx, alloc_pmem};

static fn_op_t free_op[] = {free_dram, free_tx, free_pmem, no_free};

static fn_op_t realloc_op[] = {realloc_dram, realloc_tx, realloc_pmem};

static fn_op_t add_range_op[] = {add_range_tx, add_range_nested_tx};

static fn_parse_t parse_op[] = {parse_op_mode, parse_op_mode_add_range};

static fn_op_t nestings[] = {obj_op_sim, obj_op_tx};

static fn_op_t pmdk_op[] = {pmdk_read, pmdk_write, pmdk_read_and_write, pmdk_put, pmdk_get, pmdk_update, pmdk_delete, pmdk_get_put};


/*
 * parse_pmdk_func_mode -- converts string to type_num_mode enum
 */
static enum type_pmdk_func_mode
parse_pmdk_func_mode(const char *arg)
{
	if (strcmp(arg, "read") == 0)
		return PMDK_READ;
	else if (strcmp(arg, "write") == 0)
		return PMDK_WRITE;
	else if (strcmp(arg, "read_and_write") == 0)
		return PMDK_READ_AND_WRITE;
	else if (strcmp(arg, "put") == 0)
		return PMDK_PUT;
	else if (strcmp(arg, "get") == 0)
		return PMDK_GET;
	else if (strcmp(arg, "update") == 0)
		return PMDK_UPDATE;
	else if (strcmp(arg, "delete") == 0)
		return PMDK_DELETE;
	else if (strcmp(arg, "get_put") == 0)
		return PMDK_GET_PUT;
	fprintf(stderr, "unknown anchor func mode\n");
	return PMDK_UNKNOWN;
}

/*
 * parse_type_num_mode -- converts string to type_num_mode enum
 */
static enum type_num_mode
parse_type_num_mode(const char *arg)
{
	if (strcmp(arg, "one") == 0)
		return NUM_MODE_ONE;
	else if (strcmp(arg, "per-thread") == 0)
		return NUM_MODE_PER_THREAD;
	else if (strcmp(arg, "rand") == 0)
		return NUM_MODE_RAND;
	fprintf(stderr, "unknown type number\n");
	return NUM_MODE_UNKNOWN;
}

/*
 * parse_lib_mode -- converts string to type_num_mode enum
 */
static enum lib_mode
parse_lib_mode(const char *arg)
{
	if (strcmp(arg, "dram") == 0)
		return LIB_MODE_DRAM;
	else if (strcmp(arg, "pmem") == 0)
		return LIB_MODE_OBJ_ATOMIC;
	else if (strcmp(arg, "tx") == 0)
		return LIB_MODE_OBJ_TX;
	fprintf(stderr, "unknown lib mode\n");
	return LIB_MODE_NONE;
}

static fn_type_num_t type_num_fn[] = {type_mode_one, type_mode_per_thread,
				      type_mode_rand, nullptr};

/*
 * one_num -- returns always the same number.
 */
static size_t
one_num(size_t idx)
{
	return 0;
}

/*
 * diff_num -- returns number given as argument.
 */
static size_t
diff_num(size_t idx)
{
	return idx;
}

/*
 * off_entire -- returns zero offset.
 */
static struct offset
off_entire(struct obj_tx_bench *obj_bench, size_t idx)
{
	struct offset offset;
	offset.off = 0;
	offset.size = obj_bench->sizes[obj_bench->n_oid(idx)];
	return offset;
}

/*
 * off_range -- returns offset for range in object.
 */
static struct offset
off_range(struct obj_tx_bench *obj_bench, size_t idx)
{
	struct offset offset;
	offset.size = obj_bench->sizes[0] / obj_bench->obj_args->n_ops;
	offset.off = offset.size * idx;
	return offset;
}

/*
 * rand_values -- allocates array and if range mode calculates random
 * values as allocation sizes for each object otherwise populates whole array
 * with max value. Used only when range flag set.
 */
static size_t *
rand_values(size_t min, size_t max, size_t n_ops)
{
	size_t size = max - min;
	auto *sizes = (size_t *)calloc(n_ops, sizeof(size_t));
	if (sizes == nullptr) {
		perror("calloc");
		return nullptr;
	}
	for (size_t i = 0; i < n_ops; i++)
		sizes[i] = max;
	if (min) {
		if (min > max) {
			fprintf(stderr, "Invalid size\n");
			free(sizes);
			return nullptr;
		}
		for (size_t i = 0; i < n_ops; i++)
			sizes[i] = (rand() % size) + min;
	}
	return sizes;
}

/*
 * obj_tx_pmdk_op -- main operations of the pmdk operation benchmarks.
 */
static int
obj_tx_pmdk_op(struct benchmark *bench, struct operation_info *info)
{
	auto *obj_bench = (struct obj_tx_bench *)pmembench_get_priv(bench);
	auto *obj_worker = (struct obj_tx_worker *)info->worker->priv;
	unsigned op_calls = info->args->internal_repeats / obj_bench->obj_args->tx_ops / info->args->n_threads;
	for (unsigned i = 0 ; i < op_calls ; i++) {
		if (pmdk_op[obj_bench->pmdk_func](obj_bench, info->worker,
					    info->index) != 0)
			return -1;
	}
	obj_worker->tx_level = 0;
	return 0;
}

/*
 * obj_tx_add_range_op -- main operations of the obj_tx_add_range benchmark.
 */
static int
obj_tx_add_range_op(struct benchmark *bench, struct operation_info *info)
{
	auto *obj_bench = (struct obj_tx_bench *)pmembench_get_priv(bench);
	auto *obj_worker = (struct obj_tx_worker *)info->worker->priv;
	if (add_range_op[obj_bench->lib_op](obj_bench, info->worker,
					    info->index) != 0)
		return -1;
	obj_worker->tx_level = 0;
	return 0;
}

/*
 * obj_tx_op -- main operation for obj_tx_alloc(), obj_tx_free() and
 * obj_tx_realloc() benchmarks.
 */
static int
obj_tx_op(struct benchmark *bench, struct operation_info *info)
{
	auto *obj_bench = (struct obj_tx_bench *)pmembench_get_priv(bench);
	auto *obj_worker = (struct obj_tx_worker *)info->worker->priv;
	int ret = nestings[obj_bench->nesting_mode](obj_bench, info->worker,
						    info->index);
	obj_worker->tx_level = 0;
	return ret;
}

/*
 * obj_tx_init_worker -- common part for the worker initialization functions
 * for transactional benchmarks.
 */
static int
obj_tx_init_worker(struct benchmark *bench, struct benchmark_args *args,
		   struct worker_info *worker)
{
	auto *obj_bench = (struct obj_tx_bench *)pmembench_get_priv(bench);
	auto *obj_worker =
		(struct obj_tx_worker *)calloc(1, sizeof(struct obj_tx_worker));
	if (obj_worker == nullptr) {
		perror("calloc");
		return -1;
	}
	worker->priv = obj_worker;
	obj_worker->tx_level = 0;
	obj_worker->max_level = obj_bench->obj_args->nested;
	if (obj_bench->lib_mode != LIB_MODE_DRAM)
		obj_worker->oids = (TOID(struct item) *)calloc(
			obj_bench->n_objs, sizeof(TOID(struct item)));
	else
		obj_worker->items =
			(char **)calloc(obj_bench->n_objs, sizeof(char *));
	if (obj_worker->oids == nullptr && obj_worker->items == nullptr) {
		free(obj_worker);
		perror("calloc");
		return -1;
	}
	return 0;
}

/*
 * obj_tx_free_init_worker_alloc_obj -- special part for the worker
 * initialization function for benchmarks which needs allocated objects
 * before operation.
 */
static int
obj_tx_init_worker_alloc_obj(struct benchmark *bench,
			     struct benchmark_args *args,
			     struct worker_info *worker)
{
	unsigned i;
	if (obj_tx_init_worker(bench, args, worker) != 0)
		return -1;

	auto *obj_bench = (struct obj_tx_bench *)pmembench_get_priv(bench);
	auto *obj_worker = (struct obj_tx_worker *)worker->priv;
	for (i = 0; i < obj_bench->n_objs; i++) {
		if (alloc_op[obj_bench->lib_mode](obj_bench, worker, i) != 0)
			goto out;
	}
	return 0;
out:
	for (; i > 0; i--)
		free_op[obj_bench->lib_mode](obj_bench, worker, i - 1);
	if (obj_bench->lib_mode == LIB_MODE_DRAM)
		free(obj_worker->items);
	else
		free(obj_worker->oids);
	free(obj_worker);
	return -1;
}

/*
 * obj_tx_exit_worker -- common part for the worker de-initialization.
 */
static void
obj_tx_exit_worker(struct benchmark *bench, struct benchmark_args *args,
		   struct worker_info *worker)
{
	auto *obj_bench = (struct obj_tx_bench *)pmembench_get_priv(bench);
	auto *obj_worker = (struct obj_tx_worker *)worker->priv;
	for (unsigned i = 0; i < obj_bench->n_objs; i++)
		free_op[obj_bench->lib_op_free](obj_bench, worker, i);

	if (obj_bench->lib_mode == LIB_MODE_DRAM)
		free(obj_worker->items);
	else
		free(obj_worker->oids);
	free(obj_worker);
}

/*
 * obj_tx_pmdk_init -- specific part of the obj_tx_pmdk initialization.
 */
static int
obj_tx_pmdk_init(struct benchmark *bench, struct benchmark_args *args)
{
	if (obj_tx_init(bench, args) != 0)
		return -1;

	auto *obj_bench = (struct obj_tx_bench *)pmembench_get_priv(bench);
	obj_bench->fn_op = pmdk_op;

	/*
	 * Generally all objects which will be allocated during main operation
	 * need to be released. Only exception is situation where transaction
	 * (inside which object is allocating) is aborted. Then object is not
	 * allocated so there is no need to free it in exit operation.
	 */
	if (obj_bench->lib_op == LIB_MODE_OBJ_TX &&
	    obj_bench->op_mode != OP_MODE_COMMIT)
		obj_bench->lib_op_free = LIB_MODE_NONE;
	return 0;
}

/*
 * obj_tx_add_range_init -- specific part of the obj_tx_add_range
 * benchmark initialization.
 */
static int
obj_tx_add_range_init(struct benchmark *bench, struct benchmark_args *args)
{
	auto *obj_args = (struct obj_tx_args *)args->opts;
	obj_args->parse_mode = PARSE_OP_MODE_ADD_RANGE;
	if (args->n_ops_per_thread > MAX_OPS)
		args->n_ops_per_thread = MAX_OPS;
	if (obj_tx_init(bench, args) != 0)
		return -1;

	auto *obj_bench = (struct obj_tx_bench *)pmembench_get_priv(bench);

	obj_bench->n_oid = diff_num;
	if (obj_bench->op_mode < OP_MODE_ALL_OBJ) {
		obj_bench->n_oid = one_num;
		obj_bench->n_objs = 1;
	}
	obj_bench->fn_off = off_entire;
	if (obj_bench->op_mode == OP_MODE_ONE_OBJ_RANGE ||
	    obj_bench->op_mode == OP_MODE_ONE_OBJ_NESTED_RANGE) {
		obj_bench->fn_off = off_range;
		if (args->n_ops_per_thread > args->dsize)
			args->dsize = args->n_ops_per_thread;

		obj_bench->sizes[0] = args->dsize;
	}
	obj_bench->lib_op = (obj_bench->op_mode == OP_MODE_ONE_OBJ ||
			     obj_bench->op_mode == OP_MODE_ALL_OBJ)
		? ADD_RANGE_MODE_ONE_TX
		: ADD_RANGE_MODE_NESTED_TX;
	return 0;
}

/*
 * obj_tx_free_init -- specific part of the obj_tx_free initialization.
 */
static int
obj_tx_free_init(struct benchmark *bench, struct benchmark_args *args)
{
	if (obj_tx_init(bench, args) != 0)
		return -1;

	auto *obj_bench = (struct obj_tx_bench *)pmembench_get_priv(bench);
	obj_bench->fn_op = free_op;

	/*
	 * Generally all objects which were allocated during worker
	 * initialization are released in main operation so there is no need to
	 * free them in exit operation. Only exception is situation where
	 * transaction (inside which object is releasing) is aborted.
	 * Then object is not released so there there is necessary to free it
	 * in exit operation.
	 */
	if (!(obj_bench->lib_op == LIB_MODE_OBJ_TX &&
	      obj_bench->op_mode != OP_MODE_COMMIT))
		obj_bench->lib_op_free = LIB_MODE_NONE;
	return 0;
}

/*
 * obj_tx_alloc_init -- specific part of the obj_tx_alloc initialization.
 */
static int
obj_tx_alloc_init(struct benchmark *bench, struct benchmark_args *args)
{
	if (obj_tx_init(bench, args) != 0)
		return -1;

	auto *obj_bench = (struct obj_tx_bench *)pmembench_get_priv(bench);
	obj_bench->fn_op = alloc_op;

	/*
	 * Generally all objects which will be allocated during main operation
	 * need to be released. Only exception is situation where transaction
	 * (inside which object is allocating) is aborted. Then object is not
	 * allocated so there is no need to free it in exit operation.
	 */
	if (obj_bench->lib_op == LIB_MODE_OBJ_TX &&
	    obj_bench->op_mode != OP_MODE_COMMIT)
		obj_bench->lib_op_free = LIB_MODE_NONE;
	return 0;
}

/*
 * obj_tx_realloc_init -- specific part of the obj_tx_realloc initialization.
 */
static int
obj_tx_realloc_init(struct benchmark *bench, struct benchmark_args *args)
{
	if (obj_tx_init(bench, args) != 0)
		return -1;

	auto *obj_bench = (struct obj_tx_bench *)pmembench_get_priv(bench);
	obj_bench->resizes =
		rand_values(obj_bench->obj_args->min_rsize,
			    obj_bench->obj_args->rsize, args->n_ops_per_thread);
	if (obj_bench->resizes == nullptr) {
		obj_tx_exit(bench, args);
		return -1;
	}
	obj_bench->fn_op = realloc_op;
	return 0;
}

/*
 * obj_tx_init -- common part of the benchmark initialization for transactional
 * benchmarks in their init functions. Parses command line arguments, set
 * variables and creates persistent pool.
 */
int
obj_tx_init(struct benchmark *bench, struct benchmark_args *args)
{
	assert(bench != nullptr);
	assert(args != nullptr);
	assert(args->opts != nullptr);

	char path[PATH_MAX];
	if (util_safe_strcpy(path, args->fname, sizeof(path)) != 0)
		return -1;

	enum file_type type = util_file_get_type(args->fname);
	if (type == OTHER_ERROR) {
		fprintf(stderr, "could not check type of file %s\n",
			args->fname);
		return -1;
	}

	pmembench_set_priv(bench, &obj_bench);

	obj_bench.obj_args = (struct obj_tx_args *)args->opts;
	obj_bench.obj_args->obj_size = args->dsize;
	obj_bench.obj_args->n_ops = args->n_ops_per_thread;
	obj_bench.n_objs = args->n_ops_per_thread;

	obj_bench.lib_op = obj_bench.obj_args->lib != nullptr
		? parse_lib_mode(obj_bench.obj_args->lib)
		: LIB_MODE_OBJ_ATOMIC;

	if (obj_bench.lib_op == LIB_MODE_NONE)
		return -1;
	
	obj_bench.pmdk_func = obj_bench.obj_args->pmdk_func != nullptr
		? parse_pmdk_func_mode(obj_bench.obj_args->pmdk_func)
		: PMDK_READ;
	if (obj_bench.pmdk_func == PMDK_UNKNOWN)
		return -1;

	obj_bench.lib_mode = obj_bench.lib_op == LIB_MODE_DRAM
		? LIB_MODE_DRAM
		: LIB_MODE_OBJ_ATOMIC;

	obj_bench.lib_op_free = obj_bench.lib_mode;

	obj_bench.nesting_mode = obj_bench.lib_op == LIB_MODE_OBJ_TX
		? NESTING_MODE_TX
		: NESTING_MODE_SIM;

	/*
	 * Multiplication by FACTOR prevents from out of memory error
	 * as the actual size of the allocated persistent objects
	 * is always larger than requested.
	 */
	size_t dsize = obj_bench.obj_args->rsize > args->dsize
		? obj_bench.obj_args->rsize
		: args->dsize;
	size_t psize = args->n_ops_per_thread * (dsize + ALLOC_OVERHEAD) *
					args->n_threads;
					
	//if (args->internal_repeats != 0)
	//	psize *= args->internal_repeats;		

	psize += PMEMOBJ_MIN_POOL;
	psize = (size_t)(psize * FACTOR);

	/*
	 * When adding all allocated objects to undo log there is necessary
	 * to prepare larger pool to prevent out of memory error.
	 */
	if (obj_bench.op_mode == OP_MODE_ALL_OBJ ||
	    obj_bench.op_mode == OP_MODE_ALL_OBJ_NESTED)
		psize *= 2;

	obj_bench.op_mode = parse_op[obj_bench.obj_args->parse_mode](
		obj_bench.obj_args->operation);
	if (obj_bench.op_mode == OP_MODE_UNKNOWN) {
		fprintf(stderr, "operation mode unknown\n");
		return -1;
	}

	obj_bench.type_mode = parse_type_num_mode(obj_bench.obj_args->type_num);
	if (obj_bench.type_mode == NUM_MODE_UNKNOWN)
		return -1;

	obj_bench.fn_type_num = type_num_fn[obj_bench.type_mode];
	if (obj_bench.type_mode == NUM_MODE_RAND) {
		obj_bench.random_types =
			rand_values(1, UINT32_MAX, args->n_ops_per_thread);
		if (obj_bench.random_types == nullptr)
			return -1;
	}
	obj_bench.sizes = rand_values(obj_bench.obj_args->min_size,
				      obj_bench.obj_args->obj_size,
				      args->n_ops_per_thread);
	if (obj_bench.sizes == nullptr)
		goto free_random_types;

	if (obj_bench.lib_mode == LIB_MODE_DRAM)
		return 0;

	/* Create pmemobj pool. */
	if (args->is_poolset || type == TYPE_DEVDAX) {
		if (args->fsize < psize) {
			fprintf(stderr, "file size too large\n");
			goto free_all;
		}

		psize = 0;
	} else if (args->is_dynamic_poolset) {
		int ret = dynamic_poolset_create(args->fname, psize);
		if (ret == -1)
			goto free_all;

		if (util_safe_strcpy(path, POOLSET_PATH, sizeof(path)) != 0)
			goto free_all;

		psize = 0;
	}

	obj_bench.pop = pmemobj_create(path, LAYOUT_NAME, psize, args->fmode);
	if (obj_bench.pop == nullptr) {
		perror("pmemobj_create");
		goto free_all;
	}

	return 0;
free_all:
	free(obj_bench.sizes);
free_random_types:
	if (obj_bench.type_mode == NUM_MODE_RAND)
		free(obj_bench.random_types);
	return -1;
}

/*
 * obj_tx_exit -- common part for the exit function of the transactional
 * benchmarks in their exit functions.
 */
int
obj_tx_exit(struct benchmark *bench, struct benchmark_args *args)
{
	auto *obj_bench = (struct obj_tx_bench *)pmembench_get_priv(bench);
	if (obj_bench->lib_mode != LIB_MODE_DRAM)
		pmemobj_close(obj_bench->pop);

	free(obj_bench->sizes);
	if (obj_bench->type_mode == NUM_MODE_RAND)
		free(obj_bench->random_types);
	return 0;
}

/*
 * obj_tx_realloc_exit -- common part for the exit function of the transactional
 * benchmarks in their exit functions.
 */
static int
obj_tx_realloc_exit(struct benchmark *bench, struct benchmark_args *args)
{
	auto *obj_bench = (struct obj_tx_bench *)pmembench_get_priv(bench);
	free(obj_bench->resizes);
	return obj_tx_exit(bench, args);
}

/* Array defining common command line arguments. */
static struct benchmark_clo obj_tx_clo[11];
static int extra_nclos = 3;

static struct benchmark_info obj_tx_alloc;
static struct benchmark_info obj_tx_free;
static struct benchmark_info obj_tx_realloc;
static struct benchmark_info obj_tx_add_range;

static struct benchmark_info obj_tx_read;
static struct benchmark_info obj_tx_write;
static struct benchmark_info obj_tx_read_and_write;
static struct benchmark_info obj_tx_put;
static struct benchmark_info obj_tx_get;
static struct benchmark_info obj_tx_update;
static struct benchmark_info obj_tx_delete;
static struct benchmark_info obj_tx_get_put;

CONSTRUCTOR(pmemobj_tx_constructor)
void
pmemobj_tx_constructor(void)
{
	obj_tx_clo[0].opt_short = 'T';
	obj_tx_clo[0].opt_long = "type-number";
	obj_tx_clo[0].descr = "Type number - one, rand, per-thread";
	obj_tx_clo[0].def = "one";
	obj_tx_clo[0].type = CLO_TYPE_STR;
	obj_tx_clo[0].off = clo_field_offset(struct obj_tx_args, type_num);

	obj_tx_clo[1].opt_short = 'O';
	obj_tx_clo[1].opt_long = "operation";
	obj_tx_clo[1].descr = "Type of operation";
	obj_tx_clo[1].def = "basic";
	obj_tx_clo[1].off = clo_field_offset(struct obj_tx_args, operation);
	obj_tx_clo[1].type = CLO_TYPE_STR;

	obj_tx_clo[2].opt_short = 'm';
	obj_tx_clo[2].opt_long = "min-size";
	obj_tx_clo[2].type = CLO_TYPE_UINT;
	obj_tx_clo[2].descr = "Minimum allocation size";
	obj_tx_clo[2].off = clo_field_offset(struct obj_tx_args, min_size);
	obj_tx_clo[2].def = "0";
	obj_tx_clo[2].type_uint.size =
		clo_field_size(struct obj_tx_args, min_size);
	obj_tx_clo[2].type_uint.base = CLO_INT_BASE_DEC | CLO_INT_BASE_HEX;
	obj_tx_clo[2].type_uint.min = 0;
	obj_tx_clo[2].type_uint.max = UINT_MAX;
	/*
	 * nclos field in benchmark_info structures is decremented to make this
	 * options available only for obj_tx_alloc, obj_tx_free and
	 * obj_tx_realloc benchmarks.
	 */
	obj_tx_clo[3].opt_short = 'L';
	obj_tx_clo[3].opt_long = "lib";
	obj_tx_clo[3].descr = "Type of library";
	obj_tx_clo[3].def = "tx";
	obj_tx_clo[3].off = clo_field_offset(struct obj_tx_args, lib);
	obj_tx_clo[3].type = CLO_TYPE_STR;

	obj_tx_clo[4].opt_short = 'N';
	obj_tx_clo[4].opt_long = "nestings";
	obj_tx_clo[4].type = CLO_TYPE_UINT;
	obj_tx_clo[4].descr = "Number of nested transactions";
	obj_tx_clo[4].off = clo_field_offset(struct obj_tx_args, nested);
	obj_tx_clo[4].def = "0";
	obj_tx_clo[4].type_uint.size =
		clo_field_size(struct obj_tx_args, nested);
	obj_tx_clo[4].type_uint.base = CLO_INT_BASE_DEC | CLO_INT_BASE_HEX;
	obj_tx_clo[4].type_uint.min = 0;
	obj_tx_clo[4].type_uint.max = MAX_OPS;

	obj_tx_clo[5].opt_short = 'r';
	obj_tx_clo[5].opt_long = "min-rsize";
	obj_tx_clo[5].type = CLO_TYPE_UINT;
	obj_tx_clo[5].descr = "Minimum reallocation size";
	obj_tx_clo[5].off = clo_field_offset(struct obj_tx_args, min_rsize);
	obj_tx_clo[5].def = "0";
	obj_tx_clo[5].type_uint.size =
		clo_field_size(struct obj_tx_args, min_rsize);
	obj_tx_clo[5].type_uint.base = CLO_INT_BASE_DEC | CLO_INT_BASE_HEX;
	obj_tx_clo[5].type_uint.min = 0;
	obj_tx_clo[5].type_uint.max = UINT_MAX;

	obj_tx_clo[6].opt_short = 'R';
	obj_tx_clo[6].opt_long = "realloc-size";
	obj_tx_clo[6].type = CLO_TYPE_UINT;
	obj_tx_clo[6].descr = "Reallocation size";
	obj_tx_clo[6].off = clo_field_offset(struct obj_tx_args, rsize);
	obj_tx_clo[6].def = "1";
	obj_tx_clo[6].type_uint.size =
		clo_field_size(struct obj_tx_args, rsize);
	obj_tx_clo[6].type_uint.base = CLO_INT_BASE_DEC | CLO_INT_BASE_HEX;
	obj_tx_clo[6].type_uint.min = 1;
	obj_tx_clo[6].type_uint.max = ULONG_MAX;

	obj_tx_clo[7].opt_short = 'c';
	obj_tx_clo[7].opt_long = "changed-type";
	obj_tx_clo[7].descr = "Use another type number in "
			      "reallocation than in allocation";
	obj_tx_clo[7].type = CLO_TYPE_FLAG;
	obj_tx_clo[7].off = clo_field_offset(struct obj_tx_args, change_type);

	obj_tx_clo[8].opt_short = 'P';
	obj_tx_clo[8].opt_long = "pmdk-func";
	obj_tx_clo[8].descr = "Type of PMDK Func";
	obj_tx_clo[8].def = "read";
	obj_tx_clo[8].off = clo_field_offset(struct obj_tx_args, pmdk_func);
	obj_tx_clo[8].type = CLO_TYPE_STR;

	obj_tx_clo[9].opt_short = 'g';
	obj_tx_clo[9].opt_long = "get_ratio";
	obj_tx_clo[9].type = CLO_TYPE_UINT;
	obj_tx_clo[9].descr = "Read object ratio";
	obj_tx_clo[9].off = clo_field_offset(struct obj_tx_args, get_ratio);
	obj_tx_clo[9].def = "-1";
	obj_tx_clo[9].type_uint.size =
		clo_field_size(struct obj_tx_args, get_ratio);
	obj_tx_clo[9].type_uint.base = CLO_INT_BASE_DEC | CLO_INT_BASE_HEX;
	obj_tx_clo[9].type_uint.min = 0;
	obj_tx_clo[9].type_uint.max = 100;

	obj_tx_clo[10].opt_short = 't';
	obj_tx_clo[10].opt_long = "tx_ops";
	obj_tx_clo[10].type = CLO_TYPE_UINT;
	obj_tx_clo[10].descr = "Number of operations per transaction";
	obj_tx_clo[10].off = clo_field_offset(struct obj_tx_args, tx_ops);
	obj_tx_clo[10].def = "1";
	obj_tx_clo[10].type_uint.size =
		clo_field_size(struct obj_tx_args, tx_ops);
	obj_tx_clo[10].type_uint.base = CLO_INT_BASE_DEC | CLO_INT_BASE_HEX;
	obj_tx_clo[10].type_uint.min = 1;
	obj_tx_clo[10].type_uint.max = 100;

	obj_tx_alloc.name = "obj_tx_alloc";
	obj_tx_alloc.brief = "pmemobj_tx_alloc() benchmark";
	obj_tx_alloc.init = obj_tx_alloc_init;
	obj_tx_alloc.exit = obj_tx_exit;
	obj_tx_alloc.multithread = true;
	obj_tx_alloc.multiops = true;
	obj_tx_alloc.init_worker = obj_tx_init_worker;
	obj_tx_alloc.free_worker = obj_tx_exit_worker;
	obj_tx_alloc.operation = obj_tx_op;
	obj_tx_alloc.measure_time = true;
	obj_tx_alloc.clos = obj_tx_clo;
	obj_tx_alloc.nclos = ARRAY_SIZE(obj_tx_clo) - 3 - extra_nclos;
	obj_tx_alloc.opts_size = sizeof(struct obj_tx_args);
	obj_tx_alloc.rm_file = true;
	obj_tx_alloc.allow_poolset = true;
	REGISTER_BENCHMARK(obj_tx_alloc);

	obj_tx_free.name = "obj_tx_free";
	obj_tx_free.brief = "pmemobj_tx_free() benchmark";
	obj_tx_free.init = obj_tx_free_init;
	obj_tx_free.exit = obj_tx_exit;
	obj_tx_free.multithread = true;
	obj_tx_free.multiops = true;
	obj_tx_free.init_worker = obj_tx_init_worker_alloc_obj;
	obj_tx_free.free_worker = obj_tx_exit_worker;
	obj_tx_free.operation = obj_tx_op;
	obj_tx_free.measure_time = true;
	obj_tx_free.clos = obj_tx_clo;
	obj_tx_free.nclos = ARRAY_SIZE(obj_tx_clo) - 3 - extra_nclos;
	obj_tx_free.opts_size = sizeof(struct obj_tx_args);
	obj_tx_free.rm_file = true;
	obj_tx_free.allow_poolset = true;
	REGISTER_BENCHMARK(obj_tx_free);

	obj_tx_realloc.name = "obj_tx_realloc";
	obj_tx_realloc.brief = "pmemobj_tx_realloc() benchmark";
	obj_tx_realloc.init = obj_tx_realloc_init;
	obj_tx_realloc.exit = obj_tx_realloc_exit;
	obj_tx_realloc.multithread = true;
	obj_tx_realloc.multiops = true;
	obj_tx_realloc.init_worker = obj_tx_init_worker_alloc_obj;
	obj_tx_realloc.free_worker = obj_tx_exit_worker;
	obj_tx_realloc.operation = obj_tx_op;
	obj_tx_realloc.measure_time = true;
	obj_tx_realloc.clos = obj_tx_clo;
	obj_tx_realloc.nclos = ARRAY_SIZE(obj_tx_clo) - extra_nclos;
	obj_tx_realloc.opts_size = sizeof(struct obj_tx_args);
	obj_tx_realloc.rm_file = true;
	obj_tx_realloc.allow_poolset = true;
	REGISTER_BENCHMARK(obj_tx_realloc);

	obj_tx_add_range.name = "obj_tx_add_range";
	obj_tx_add_range.brief = "pmemobj_tx_add_range() benchmark";
	obj_tx_add_range.init = obj_tx_add_range_init;
	obj_tx_add_range.exit = obj_tx_exit;
	obj_tx_add_range.multithread = true;
	obj_tx_add_range.multiops = false;
	obj_tx_add_range.init_worker = obj_tx_init_worker_alloc_obj;
	obj_tx_add_range.free_worker = obj_tx_exit_worker;
	obj_tx_add_range.operation = obj_tx_add_range_op;
	obj_tx_add_range.measure_time = true;
	obj_tx_add_range.clos = obj_tx_clo;
	obj_tx_add_range.nclos = ARRAY_SIZE(obj_tx_clo) - 5 - extra_nclos;
	obj_tx_add_range.opts_size = sizeof(struct obj_tx_args);
	obj_tx_add_range.rm_file = true;
	obj_tx_add_range.allow_poolset = true;
	REGISTER_BENCHMARK(obj_tx_add_range);

	obj_tx_read.name = "obj_tx_read";
	obj_tx_read.brief = "pmemobj_tx_read() benchmark";
	obj_tx_read.init = obj_tx_pmdk_init;
	obj_tx_read.exit = obj_tx_exit;
	obj_tx_read.multithread = true;
	obj_tx_read.multiops = true;
	obj_tx_read.init_worker = obj_tx_init_worker; //obj_tx_init_worker_alloc_obj
	obj_tx_read.free_worker = obj_tx_exit_worker;
	obj_tx_read.operation = obj_tx_pmdk_op;
	obj_tx_read.measure_time = true;
	obj_tx_read.clos = obj_tx_clo;
	obj_tx_read.nclos = ARRAY_SIZE(obj_tx_clo);
	obj_tx_read.opts_size = sizeof(struct obj_tx_args);
	obj_tx_read.rm_file = true;
	obj_tx_read.allow_poolset = true;
	REGISTER_BENCHMARK(obj_tx_read);

	obj_tx_write.name = "obj_tx_write";
	obj_tx_write.brief = "pmemobj_tx_write() benchmark";
	obj_tx_write.init = obj_tx_pmdk_init;
	obj_tx_write.exit = obj_tx_exit;
	obj_tx_write.multithread = true;
	obj_tx_write.multiops = true;
	obj_tx_write.init_worker = obj_tx_init_worker;
	obj_tx_write.free_worker = obj_tx_exit_worker;
	obj_tx_write.operation = obj_tx_pmdk_op;
	obj_tx_write.measure_time = true;
	obj_tx_write.clos = obj_tx_clo;
	obj_tx_write.nclos = ARRAY_SIZE(obj_tx_clo);
	obj_tx_write.opts_size = sizeof(struct obj_tx_args);
	obj_tx_write.rm_file = true;
	obj_tx_write.allow_poolset = true;
	REGISTER_BENCHMARK(obj_tx_write);

	obj_tx_read_and_write.name = "obj_tx_read_and_write";
	obj_tx_read_and_write.brief = "pmemobj_tx_read_and_write benchmark";
	obj_tx_read_and_write.init = obj_tx_pmdk_init;
	obj_tx_read_and_write.exit = obj_tx_exit;
	obj_tx_read_and_write.multithread = true;
	obj_tx_read_and_write.multiops = true;
	obj_tx_read_and_write.init_worker = obj_tx_init_worker;
	obj_tx_read_and_write.free_worker = obj_tx_exit_worker;
	obj_tx_read_and_write.operation = obj_tx_pmdk_op;
	obj_tx_read_and_write.measure_time = true;
	obj_tx_read_and_write.clos = obj_tx_clo;
	obj_tx_read_and_write.nclos = ARRAY_SIZE(obj_tx_clo);
	obj_tx_read_and_write.opts_size = sizeof(struct obj_tx_args);
	obj_tx_read_and_write.rm_file = true;
	obj_tx_read_and_write.allow_poolset = true;
	REGISTER_BENCHMARK(obj_tx_read_and_write);

	obj_tx_put.name = "obj_tx_put";
	obj_tx_put.brief = "pmemobj_tx_put benchmark";
	obj_tx_put.init = obj_tx_pmdk_init;
	obj_tx_put.exit = obj_tx_exit;
	obj_tx_put.multithread = true;
	obj_tx_put.multiops = true;
	obj_tx_put.init_worker = obj_tx_init_worker;
	obj_tx_put.free_worker = obj_tx_exit_worker;
	obj_tx_put.operation = obj_tx_pmdk_op;
	obj_tx_put.measure_time = true;
	obj_tx_put.clos = obj_tx_clo;
	obj_tx_put.nclos = ARRAY_SIZE(obj_tx_clo);
	obj_tx_put.opts_size = sizeof(struct obj_tx_args);
	obj_tx_put.rm_file = true;
	obj_tx_put.allow_poolset = true;
	REGISTER_BENCHMARK(obj_tx_put);

	obj_tx_get.name = "obj_tx_get";
	obj_tx_get.brief = "pmemobj_tx_get benchmark";
	obj_tx_get.init = obj_tx_pmdk_init;
	obj_tx_get.exit = obj_tx_exit;
	obj_tx_get.multithread = true;
	obj_tx_get.multiops = true;
	obj_tx_get.init_worker = obj_tx_init_worker_alloc_obj; //warmup - alloc the objects
	obj_tx_get.free_worker = obj_tx_exit_worker;
	obj_tx_get.operation = obj_tx_pmdk_op;
	obj_tx_get.measure_time = true;
	obj_tx_get.clos = obj_tx_clo;
	obj_tx_get.nclos = ARRAY_SIZE(obj_tx_clo);
	obj_tx_get.opts_size = sizeof(struct obj_tx_args);
	obj_tx_get.rm_file = true;
	obj_tx_get.allow_poolset = true;
	REGISTER_BENCHMARK(obj_tx_get);

	obj_tx_update.name = "obj_tx_update";
	obj_tx_update.brief = "pmemobj_tx_update benchmark";
	obj_tx_update.init = obj_tx_pmdk_init;
	obj_tx_update.exit = obj_tx_exit;
	obj_tx_update.multithread = true;
	obj_tx_update.multiops = true;
	obj_tx_update.init_worker = obj_tx_init_worker_alloc_obj; //warmup - alloc the objects
	obj_tx_update.free_worker = obj_tx_exit_worker;
	obj_tx_update.operation = obj_tx_pmdk_op;
	obj_tx_update.measure_time = true;
	obj_tx_update.clos = obj_tx_clo;
	obj_tx_update.nclos = ARRAY_SIZE(obj_tx_clo);
	obj_tx_update.opts_size = sizeof(struct obj_tx_args);
	obj_tx_update.rm_file = true;
	obj_tx_update.allow_poolset = true;
	REGISTER_BENCHMARK(obj_tx_update);

	obj_tx_delete.name = "obj_tx_delete";
	obj_tx_delete.brief = "pmemobj_tx_delete benchmark";
	obj_tx_delete.init = obj_tx_pmdk_init;
	obj_tx_delete.exit = obj_tx_exit;
	obj_tx_delete.multithread = true;
	obj_tx_delete.multiops = true;
	obj_tx_delete.init_worker = obj_tx_init_worker_alloc_obj; //warmup - alloc the objects
	obj_tx_delete.free_worker = obj_tx_exit_worker;
	obj_tx_delete.operation = obj_tx_pmdk_op;
	obj_tx_delete.measure_time = true;
	obj_tx_delete.clos = obj_tx_clo;
	obj_tx_delete.nclos = ARRAY_SIZE(obj_tx_clo);
	obj_tx_delete.opts_size = sizeof(struct obj_tx_args);
	obj_tx_delete.rm_file = true;
	obj_tx_delete.allow_poolset = true;
	REGISTER_BENCHMARK(obj_tx_delete);

	obj_tx_get_put.name = "obj_tx_get_put";
	obj_tx_get_put.brief = "pmemobj_tx_get_put benchmark";
	obj_tx_get_put.init = obj_tx_pmdk_init;
	obj_tx_get_put.exit = obj_tx_exit;
	obj_tx_get_put.multithread = true;
	obj_tx_get_put.multiops = true;
	obj_tx_get_put.init_worker = obj_tx_init_worker_alloc_obj; //warmup - alloc the objects
	obj_tx_get_put.free_worker = obj_tx_exit_worker;
	obj_tx_get_put.operation = obj_tx_pmdk_op;
	obj_tx_get_put.measure_time = true;
	obj_tx_get_put.clos = obj_tx_clo;
	obj_tx_get_put.nclos = ARRAY_SIZE(obj_tx_clo);
	obj_tx_get_put.opts_size = sizeof(struct obj_tx_args);
	obj_tx_get_put.rm_file = true;
	obj_tx_get_put.allow_poolset = true;
	REGISTER_BENCHMARK(obj_tx_get_put);
}
