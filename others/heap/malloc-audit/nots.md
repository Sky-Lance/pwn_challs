# freeeeee
- first check tcache (fails occasionally)

- place in fastbin if possible:
    - check for trim fastbin flag - if there dont place in fastbin if bordering top
    - prevent race condition with lock
    - link to fastbin
    - check top of bin to make sure no double free
    - check size, and theres a chance its not locked, and that means its allocated

- consolidate if not mmaped

- if alloced via mmap - release via munmap


## -- int free merge chunk -- aka coalesce prev chunk

- check if top block
- check if next block is beyond arena
- check for double free
- consolidate back & write new header


## -- int free create chunk -- aka coalesce next chunk

- mark as free
- consolidate forward
- place in unsorted bin
- check if at high end of memory, if so, consolidate into top


## -- int free maybe consolidate -- ??

- if bigger than fastbin consolidation threshold, then consolidate
- if cannot heeptrim, systrim
- else, heeptrim

# malloc consolidate

- move from fast bin, consolidate, move to unsorted bin
    - using atomic exchange something, remove currenbt chunk
        - check chunk alignment, proper fastbin index, whether it is in use
    - if prev chunk not in use, coalesce backwards
    - if next chunk not in use, coalesce forwards
    - place in unsorted bin

- update top pointer


# malloccccccc

- align size

- check for arenas
    - if fail, go sysmalloc to get chunk from mmap

- check for fastbin
    - check for misalignment
    - if find other chunk with same size, store in tcache
    - keep copying, as long as bin is not empty and tcache isnt full
        - another misalignment check

- if in smallbin range
    - check for backward pointer
        - another tcache thing

- if giant req
    - first kill all fastbins (why? fragmentation issues)

- traverse free list 
    - place in bins as it goes  
        - if it's a proper fit return chunk
        - if it's small enough return the most recent non-exact fit
    - place other chunks in bins
    - few checks before placing
        - check for size validity
        - check for next chunk size validity
        - check for previous chunk's next chunk metadata
        - check for validity of doubly linked list
        - check for next's previnuse bit

- if small request
    - use last reminder (to promote locality for consecutive small requests)
        - this rule is ignored when theres an exact fit
    - remove from unsorted bin
        - takes after this instead of binning - if exact fit

- fill cache

- make sure large bins are sorted
    - for this - first speed comparisons by or with inuse
    - check if smaller than smallest
        - if true, skip
    - insertion sort algorithm?
        - check for corrupted double linked list
            - in nextsize()
            - in bk pointer

- if max number has been processsed
    - return one of the cached ones

- if all small chunks are cached
    - return one of them

- if giant request
    - scan chunks of current bin in order, to find smallest one that first
        - first check if bin is empty or if largest chunk is too small
        - skip first chunk, or rerouting required
    - insert into unsorted bin
        - if error in traversal - unsorted chunks have faulty forward or backward pointers

- check next smallest bin
    - traverse with check if set bit
        - inspect said bin 
            - if empty, clear bit
            - else, unlink, insert into unsorted
                - same check
    - if no said bin
        - go to top chunk
            - check for if top size is corrupted
        - meanwhile, consolidate all fast chunks
    - fall back to sysmalloc

    





