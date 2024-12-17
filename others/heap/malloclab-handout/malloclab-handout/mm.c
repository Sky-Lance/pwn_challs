/*
 * mm-naive.c - The fastest, least memory-efficient malloc package.
 * 
 * In this naive approach, a block is allocated by simply incrementing
 * the brk pointer. A block is pure payload. There are no headers or
 * footers. Blocks are never coalesced or reused. Realloc is
 * implemented directly using mm_malloc and mm_free.
 *
 * NOTE TO STUDENTS: Replace this header comment with your own header
 * comment that gives a high level description of your solution.
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>

#include "mm.h"
#include "memlib.h"

/*********************************************************
 * NOTE TO STUDENTS: Before you do anything else, please
 * provide your team information in the following struct.
 ********************************************************/
team_t team = {
    /* Team name */
    "vavval_squad",
    /* First member's full name */
    "vavval1",
    /* First member's email address */
    "vavvalgod@vavval.com",
    /* Second member's full name (leave blank if none) */
    "",
    /* Second member's email address (leave blank if none) */
    ""
};

/* single word (4) or double word (8) alignment */
#define ALIGNMENT 8

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(size) (((size) + (0xf)) & ~(0xf))

#define SIZE_T_SIZE (ALIGN(sizeof(size_t)))

/* Basic constants and macros */
#define WSIZE 8 /* Word and header/footer size (bytes) */
#define DSIZE 16 /* Double word size (bytes) */
#define CHUNKSIZE (1<<12) /* Extend heap by this amount (bytes) */
#define MAX(x, y) ((x) > (y)? (x) : (y))

/* Pack a size and allocated bit into a word */
#define PACK(size, alloc) ((size) | (alloc))

/* Read and write a word at address p */
#define GET(p) (*(unsigned long *)(p))
#define PUT(p, val) (*(unsigned long *)(p) = (val))

/* Read the size and allocated fields from address p */
#define GET_SIZE(p) (GET(p) & ~(0x7))
#define GET_ALLOC(p) (GET(p) & 0x1)

/* Given block ptr ptr, compute address of its header and footer */
#define HDRP(ptr) ((char *)(ptr) - WSIZE)
#define FTRP(ptr) ((char *)(ptr) + GET_SIZE(HDRP(ptr)) - DSIZE)

/* Given block ptr ptr, compute address of next and previous blocks */
#define NEXT_BLKP(ptr) ((char *)(ptr) + GET_SIZE(((char *)(ptr) - WSIZE)))
#define PREV_BLKP(ptr) ((char *)(ptr) - GET_SIZE(((char *)(ptr) - DSIZE)))

void *heap_base = NULL;

void *alloc_new(size_t size){
    int newsize = ALIGN(size);
    void *p = mem_sbrk(newsize);
    if (p == (void *)-1) {
        // printf("BRUH");
        return NULL;
    }
    else {
        *(size_t *)p = size;
        // printf("Original size, %d\n", size);
        // printf("tHIS? %p\n", p);
        PUT(HDRP(p), PACK(newsize, 1));
        PUT(FTRP(p), PACK(newsize, 1));
        PUT(HDRP(NEXT_BLKP(p)), PACK(0, 1));
        // printf("HEADER LOCATION: %p\n", HDRP(p));
        // printf("FOOTER LOCATION: %p\n", FTRP(p));
        // printf("ALLOCATED SIZE: %d\n", GET_SIZE(HDRP(p)));

        // printf("size: %d\n", newsize);
        // printf("alloc next pointer: %p\n", NEXT_BLKP(p));
        // printf("ALLOCING NEW AT: %p\n", (void *)((char *)p));
        return (void *)((char *)p);
    }
}

/* 
 * mm_init - initialize the malloc package.
 */
int mm_init(void)
{
    setvbuf(stdin, 0, _IONBF, NULL);
    setvbuf(stdout, 0, _IONBF, NULL);
    size_t newsize = CHUNKSIZE;
    newsize = 0;
    heap_base = alloc_new(newsize);
    // printf("Base: %p", heap_base);
    if (heap_base == NULL){
        return -1;
    }
    return 0;
}

static void *find_fit(size_t size) {
    void *ptr;
    void *next_ptr;

    // printf("Starting find_fit with required size: %d\n", size);
    // printf("base: %p\n", heap_base);
    // printf("base size: %d\n", GET_SIZE(HDRP(heap_base)));
    // printf("")
    for (ptr = heap_base; GET_SIZE(HDRP(ptr)) > 0; ptr = next_ptr) {
        next_ptr = NEXT_BLKP(ptr);

        // printf("Current block:\n");
        // printf("    ptr: %p\n", ptr);
        // printf("    chunk size: %d\n", GET_SIZE(HDRP(ptr)));
        // printf("    alloc: %d\n", GET_ALLOC(HDRP(ptr)));
        // printf("    next: %p\n", next_ptr);
        // printf("    next chunk size: %d\n", GET_SIZE(HDRP(next_ptr)));

        if (!GET_ALLOC(HDRP(ptr))) {
            if (size <= GET_SIZE(HDRP(ptr))) {
                // printf("FOUND FITTING BLOCK AT: %p\n", ptr);
                return ptr;
            }
        }
    }
    return NULL;
}
/* 
 * mm_malloc - Allocate a block by incrementing the brk pointer.
 *     Always allocate a block whose size is a multiple of the alignment.
 */
void *mm_malloc(size_t size)
{
    int newsize = ALIGN(size+1);
    char *ptr;
    ptr = find_fit(newsize);
    if (ptr != NULL){
        size_t oldsize = GET_SIZE(ptr-8);
        // printf("Old size: %d", oldsize);
        PUT(HDRP(ptr), PACK(oldsize, 1));
        PUT(FTRP(ptr), PACK(oldsize, 1));
        return (void *)((char *)ptr);
    }
    else{
        return alloc_new(newsize);
    }
}

// coalesce - Join freed blocks (if connected)
static void *coalesce(void *ptr)
{
    size_t prev_alloc = GET_ALLOC(HDRP(PREV_BLKP(ptr)));
    size_t next_alloc = GET_ALLOC(HDRP(NEXT_BLKP(ptr)));
    size_t size = GET_SIZE(HDRP(ptr));
    // printf("ENTERING COALESCE\n");

    if (prev_alloc && next_alloc){
        // printf("LEAVING COALESCE\n");
        return ptr;
    }
    else if (prev_alloc && !next_alloc){
        size += GET_SIZE(HDRP(NEXT_BLKP(ptr)));
        PUT(HDRP(ptr), PACK(size, 0));
        PUT(FTRP(ptr), PACK(size, 0));
        // printf("next is available");
    }
    else if (!prev_alloc && next_alloc){
        size += GET_SIZE(HDRP(PREV_BLKP(ptr)));
        PUT(FTRP(ptr), PACK(size, 0));
        PUT(HDRP(PREV_BLKP(ptr)), PACK(size, 0));
        ptr = PREV_BLKP(ptr);
        // printf("prev is available");
    }
    else{
        size += GET_SIZE(HDRP(PREV_BLKP(ptr))) + GET_SIZE(HDRP(NEXT_BLKP(ptr)));
        PUT(HDRP(PREV_BLKP(ptr)), PACK(size, 0));
        PUT(FTRP(NEXT_BLKP(ptr)), PACK(size, 0));
        ptr = PREV_BLKP(ptr);
        // printf("both are available");
    }
    return ptr;
}

/*
 * mm_free - Freeing a block does nothing.
 */
void mm_free(void *ptr)
{
    if (ptr == NULL) {
        return;
    }

    size_t size = GET_SIZE(HDRP(ptr));
    // printf("writing to: %p", HDRP(ptr));
    // printf("FREED CHuNK SIZE: %d\n", size);
    coalesce(ptr);
    PUT(HDRP(ptr), PACK(size, 0));
    PUT(FTRP(ptr), PACK(size, 0));
    // printf("FREEING THIS CHUNK: %p\n", ptr);
}

/*
 * mm_realloc - Implemented simply in terms of mm_malloc and mm_free (NOT USING THIS)
 */
void *mm_realloc(void *ptr, size_t size)
{
}
