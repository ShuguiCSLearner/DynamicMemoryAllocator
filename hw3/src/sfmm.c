/**
 * Do not submit your assignment with a main function in this file.
 * If you submit with a main function in this file, you will get a zero.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "debug.h"
#include "sfmm.h"
#include <errno.h>

#define HEADER 8;
#define FOOTER_SIZE 8;
#define PAGEMEM 4096 //4096 byte
#define EPILOGUE_SIZE 8  //8 bytes
#define PROLOGUE_SIZE 32 //32 bytes
#define MINIMUM_SIZE 32

int init_heap(){
    void *startOfNewPage;
    void *heapStart;
    void *heapEnd;
    startOfNewPage=sf_mem_grow();
    //if new page cannot be added, then malloc should fail
    // set ENOMEM and return NULL
    if(startOfNewPage==NULL){
        sf_errno=ENOMEM;
        //return 0 means this failed
        return 0;
    }
    heapStart=sf_mem_start();
    //locate prologue block
    //printf("addr of free blk %p\n", heapStart);
    sf_block *prologue=heapStart;
    //locate init_freeblock which is 32 byte after prologue
    sf_block *free_blk=heapStart+32;
    //printf("addr of free blk %p\n", free_blk);
    //new heap end
    heapEnd=sf_mem_end();
    //locate epilogue block
    sf_block *epilogue=heapEnd-EPILOGUE_SIZE;
    //write in their size with alloc
    prologue->header=((32| THIS_BLOCK_ALLOCATED));
    epilogue->header=(0| THIS_BLOCK_ALLOCATED);
    free_blk->header=(sf_mem_end()-sf_mem_start()-EPILOGUE_SIZE-PROLOGUE_SIZE)| PREV_BLOCK_ALLOCATED;
    //find the addr of footer and set it to same as header
    sf_footer *footer=heapEnd-EPILOGUE_SIZE-FOOTER_SIZE;
    *footer= free_blk->header;
    //init free list
    //each index should be a doubly linked list point to self at first
    for(int i=0;i<NUM_FREE_LISTS;i++){
        sf_free_list_heads[i].body.links.next=&sf_free_list_heads[i];
        sf_free_list_heads[i].body.links.prev=&sf_free_list_heads[i];
    }
    //init quick list
    for (int i=0;i<NUM_QUICK_LISTS;i++){
        sf_quick_lists[i].length=0;
        sf_quick_lists[i].first=NULL;
    }
    //place the free block in free list which is 8th list
    free_blk->body.links.next=&sf_free_list_heads[7];
    free_blk->body.links.prev=&sf_free_list_heads[7];
    sf_free_list_heads[7].body.links.next=free_blk;
    sf_free_list_heads[7].body.links.prev=free_blk;
    return 1;
}

    //find the needed size to be allocated
    //check min reached and check multiple of 8
size_t find_required_block_size(size_t size){
    size_t size_with_head=size+HEADER;
    //check if it is less than minimum size of 32
    if(size_with_head<MINIMUM_SIZE){
        size_with_head=MINIMUM_SIZE;
    }
    //check if it need padding
    else if(size_with_head%8!=0){
        size_t remainder=size_with_head%8;
        size_with_head+=(8-remainder);
    }
    return size_with_head;
}
void *find_qk_list_memory(size_t required_block_size){
    //check if size is greater than limit of quicklist (32+(19*8))
    //search quicklist
    //printf("%ld\n",required_block_size);
    size_t index_of_quick=(required_block_size-32)/8;
    //printf("%ld\n",index_of_quick);
    if(index_of_quick>19){
        return NULL;
    }
    if (sf_quick_lists[index_of_quick].first!=NULL && index_of_quick<=19 && sf_quick_lists[index_of_quick].length!=0){
        //found it, add 8 to locate the payload area
        void * malloc_ptr=(&sf_quick_lists[index_of_quick].first)+8;

        sf_quick_lists[index_of_quick].length-=1;
        if(sf_quick_lists[index_of_quick].length==0){
            sf_quick_lists[index_of_quick].first=NULL;
        }
        else{
            sf_quick_lists[index_of_quick].first=sf_quick_lists[index_of_quick].first->body.links.next;
        }
        return malloc_ptr;
    }
    else{
        return NULL;
    }
}

int locate_free_list_index(size_t required_block_size){
    int free_list_index;
    //printf("required_block_size byte is: %ld",required_block_size);
    required_block_size=required_block_size/32;
    //printf("required_block_size byte is: %ld",required_block_size);
    //locate the free list index
    int temp=256; //256 bytes
    for(int i=9; i>=0;i--){
        if(temp<required_block_size){
            //found the correct index
            //printf("true");
            free_list_index=i;
            break;
        }
        else{
            //printf("false");
            temp/=2;
        }
    }
    return free_list_index;
}
void remove_from_free_list(sf_block* allocated_block){
    sf_block* prev_block=allocated_block->body.links.prev;
    prev_block->body.links.next = allocated_block->body.links.next;
    sf_block* next_block=allocated_block->body.links.next;
    next_block->body.links.prev = allocated_block->body.links.prev;
}
void place_free_block_to_free_list(sf_block * new_block){
    int new_block_index=locate_free_list_index(new_block->header & 0xFFFFFFFFFFFFFFF8);
    sf_block* third_node_block=sf_free_list_heads[new_block_index].body.links.next;
    new_block->body.links.next=third_node_block;
    new_block->body.links.prev=&sf_free_list_heads[new_block_index];
    third_node_block->body.links.prev=new_block;
    sf_free_list_heads[new_block_index].body.links.next=new_block;
}
void *find_free_list_memory(size_t required_block_size){
    int free_list_index=locate_free_list_index(required_block_size);


    //start from the found index and search to the end check
    for(int i=free_list_index; i<=9;i++){
        //this is the dummy node pointer
        //printf("free_list_index: %d \n",i);

        //sf_block current_header_dummy=sf_free_list_heads[i];

        sf_block *next_block=  sf_free_list_heads[i].body.links.next;
        //search the particular free list until it search back to its dummy header
        //until it return to its header
        while(next_block != &sf_free_list_heads[i])
        {
            //and with 11111111 11111111 11111111 11111111 11111111 11111111 11111111 11111000 to find the size
            size_t next_block_size=(next_block->header) & 0xFFFFFFFFFFFFFFF8;
            //check splinter
            if(next_block_size>=required_block_size){
                size_t left_size=next_block_size-required_block_size;
                //no splinter
                //use all the block
                //remove from the free list
                //set next block in heap prev alloc to 1
                    //if next block is free, then we need to set footer as header
                if (left_size<32){
                    remove_from_free_list(next_block);
                    //find next block
                    sf_block *next_block_in_heap= (void*)next_block + next_block_size;
                    //check if it has footer
                    //if alloc !=1 and in quicklist !=1, then it must have footer
                    next_block_in_heap->header=(next_block_in_heap->header | PREV_BLOCK_ALLOCATED);
                    if( (next_block_in_heap->header & THIS_BLOCK_ALLOCATED) != THIS_BLOCK_ALLOCATED && (next_block_in_heap->header & IN_QUICK_LIST) != IN_QUICK_LIST) {
                        //it has footer, set the footer to header
                        sf_footer *footer= (void*) next_block_in_heap + (next_block_in_heap->header & 0xFFFFFFFFFFFFFFF8) - 8;
                        *footer= next_block_in_heap->header;
                    }
                    return (void*)next_block+8;
                }
                //split it because it is greater than 32
                else{
                    //find the remaining size header->
                    //remove the orig block
                    remove_from_free_list(next_block);
                    sf_block * left_over_block=  (void*)next_block+required_block_size;
                    //update its size and prv alloc to 1
                    left_over_block->header= left_size| PREV_BLOCK_ALLOCATED;
                    //find its footer and update it
                    sf_footer *left_over_block_footer= (void*)left_over_block+left_size-8;
                    *left_over_block_footer=left_over_block->header;

                    //change the size and save the last 3 bits
                    //update header and footer for remaining block
                    size_t temp =next_block->header & 0x00000007;
                    //set the footer and header for this new allocated block
                    sf_block *allocated_block=(void*)next_block;
                    //printf("addr of allocaed block: %p",allocated_block);
                    allocated_block->header=required_block_size | temp;
                    //set to alloc
                    allocated_block->header=allocated_block->header | THIS_BLOCK_ALLOCATED;
                    place_free_block_to_free_list(left_over_block);
                        //place_free_block_to_free_list(*next_block);
                    //}
                    return (void*)allocated_block+8;
                }
            }
            //go to next block
            next_block=next_block->body.links.next;
        }
    }
    return NULL;
}

int check_size_matches_quick(size_t pp_block_size){
    if(pp_block_size>184){
        return 0;
    }
    if(pp_block_size<32){
        return 0;
    }
    if((pp_block_size-32)%8!=0){
        return 0;
    }
    return 1;

}
int insert_into_quick_list(sf_block *pp_block, size_t pp_block_size){
    //success return 1
    //fail return 0-> need to flush
    size_t index_of_quick=(pp_block_size-32)/8;
    if(sf_quick_lists[index_of_quick].length==5){
        return 0;
    }
    //set the quicklist header into allocated and in quicklist to 1
    pp_block->header=((pp_block->header | THIS_BLOCK_ALLOCATED) | IN_QUICK_LIST);
    //it is not full, put into quicklist and add the length by 1
    sf_quick_lists[index_of_quick].length=sf_quick_lists[index_of_quick].length+1;
    //put into quick list and set it as first
    pp_block->body.links.next=sf_quick_lists[index_of_quick].first;
    sf_quick_lists[index_of_quick].first=pp_block;
    return 1;
}
void coalsce_with_adjacent(sf_block *block_for_flush){
    //check previous and next block is allocated or not
    size_t prev_alloc_flag=block_for_flush->header & PREV_BLOCK_ALLOCATED;
    //if prev alloc flag == prevblock
    size_t size_of_block_for_flush=block_for_flush->header & 0xFFFFFFFFFFFFFFF8;
    //find the next block header
    sf_block *next_block= (void*)block_for_flush+size_of_block_for_flush;
    //if next_block_alloc = this block alloc -> allocated
    size_t next_block_alloc_flag= next_block->header & THIS_BLOCK_ALLOCATED;
    //prev block is not allocated  and next block is also not allocated
    if((prev_alloc_flag!=PREV_BLOCK_ALLOCATED) && (next_block_alloc_flag!= THIS_BLOCK_ALLOCATED)){
        //find the footer of prev block
        //find the prev block size
        sf_footer *footer= (void*) block_for_flush - 8;
        size_t prev_footer_size= *footer & 0xFFFFFFFFFFFFFFF8;
        //find the header of prev block
        sf_block * prev_block= (void*) block_for_flush-prev_footer_size;
        //disconnect both prev and next block from free list
        remove_from_free_list(prev_block);
        remove_from_free_list(next_block);
        //combine them and set header and footer
        //add all of their size from three block
        //keep the prev block last 3 bit
        size_t total_size=prev_footer_size+size_of_block_for_flush+ (next_block->header & 0xFFFFFFFFFFFFFFF8);
        size_t last_three_bit_prev_block=*footer & 0x00000007;
        //set the header
        prev_block->header= total_size|last_three_bit_prev_block;
        sf_footer *new_footer= (void*)prev_block+total_size-8;
        *new_footer=prev_block->header;

        //set the next heap size prv alloc to 0
        sf_block *block_for_flush_next= (void*) prev_block + (prev_block->header & 0xFFFFFFFFFFFFFFF8);
        block_for_flush_next->header=block_for_flush_next->header & ~PREV_BLOCK_ALLOCATED;
        place_free_block_to_free_list(prev_block);
    }
    //prev block is not allocated  and next block is allocated
    else if((prev_alloc_flag!=PREV_BLOCK_ALLOCATED) && (next_block_alloc_flag== THIS_BLOCK_ALLOCATED)){
        //only need to combine prev and current block
        //find the footer of prev block
        //find the prev block size
        sf_footer *footer= (void*) block_for_flush - 8;
        size_t prev_footer_size= *footer & 0xFFFFFFFFFFFFFFF8;
        //find the header of prev block
        sf_block * prev_block= (void*) block_for_flush-prev_footer_size;
        //disconnect both prev from free list
        remove_from_free_list(prev_block);
        //combine them and set header and footer
        //add all of their size from prev and curr block
        //keep the prev block last 3 bit
        size_t total_size=prev_footer_size+size_of_block_for_flush;
        size_t last_three_bit_prev_block=*footer & 0x00000007;
        //set the header
        prev_block->header= total_size|last_three_bit_prev_block;
        sf_footer *new_footer= (void*)prev_block+total_size-8;
        *new_footer=prev_block->header;

        //set the next heap size prv alloc to 0
        sf_block *block_for_flush_next= (void*) prev_block + (prev_block->header & 0xFFFFFFFFFFFFFFF8);
        block_for_flush_next->header=block_for_flush_next->header & ~PREV_BLOCK_ALLOCATED;
        place_free_block_to_free_list(prev_block);
    }
    //prev block is allocated  and next block is not  allocated
    else if((prev_alloc_flag==PREV_BLOCK_ALLOCATED) && (next_block_alloc_flag!= THIS_BLOCK_ALLOCATED)){
        //only need to combine current block and next block
        //disconnect next block
        remove_from_free_list(next_block);
        //find size of new block
        size_t total_size= size_of_block_for_flush+ (next_block->header & 0xFFFFFFFFFFFFFFF8);
        //new block is not in qk list, prv is alloc, and alloc is 0
        block_for_flush->header= ((total_size| PREV_BLOCK_ALLOCATED) & ~IN_QUICK_LIST) & ~THIS_BLOCK_ALLOCATED;
        sf_footer *new_footer= (void*)block_for_flush+total_size-8;
        *new_footer=block_for_flush->header;

        //set the next heap size prv alloc to 0
        sf_block *block_for_flush_next= (void*) block_for_flush + (block_for_flush->header & 0xFFFFFFFFFFFFFFF8);
        block_for_flush_next->header=block_for_flush_next->header & ~PREV_BLOCK_ALLOCATED;
        //printf("herehereherhehrehrehrh \n");
        //printf("addr of block for flush: %p \n",block_for_flush_next);
        place_free_block_to_free_list(block_for_flush);
    }
    //both prev and next are allocated
    else if((prev_alloc_flag==PREV_BLOCK_ALLOCATED) && (next_block_alloc_flag== THIS_BLOCK_ALLOCATED)){
        //no disconnection
        //reset the header and footer, set only prev alloc to 1
        block_for_flush->header=block_for_flush->header & 0xFFFFFFFFFFFFFFF8;
        block_for_flush->header=block_for_flush->header | PREV_BLOCK_ALLOCATED;
        sf_footer *new_footer= (void*)block_for_flush+(block_for_flush->header & 0xFFFFFFFFFFFFFFF8)-8;
        *new_footer=block_for_flush->header;

        //set the next heap size prv alloc to 0
        sf_block *block_for_flush_next= (void*) block_for_flush + (block_for_flush->header & 0xFFFFFFFFFFFFFFF8);
        block_for_flush_next->header=block_for_flush_next->header & ~PREV_BLOCK_ALLOCATED;
        place_free_block_to_free_list(block_for_flush);
    }
}

void flush_quick_list(size_t pp_block_size){
    size_t index_of_quick=(pp_block_size-32)/8;
    //this corresponding index has length of 5
    for(int i=1; i<=5; i++){
        //find the block need to be flush, coascle it, add to free list
        sf_block* block_for_flush=sf_quick_lists[index_of_quick].first;
        //update the first to its next
        sf_quick_lists[index_of_quick].first=block_for_flush->body.links.next;
        coalsce_with_adjacent(block_for_flush);
    }
    //reset it
    sf_quick_lists[index_of_quick].first=NULL;
    sf_quick_lists[index_of_quick].length=0;
}

void *sf_malloc(size_t size) {
    // TO BE IMPLEMENTED
    //If size is 0, then NULL is returned without setting sf_errno.
    if(size==0){
        return NULL;
    }
    //If size is nonzero, then if the allocation is successful a pointer to a valid region of
    //memory of the requested size is returned.  If the allocation is not successful, then
    //NULL is returned and sf_errno is set to ENOMEM.

    //check if heapStart and heapEnd point to same address -> first allocation request check 
    void *heapStart;
    heapStart=sf_mem_start();
    void *heapEnd;
    heapEnd=sf_mem_end();

    //init heap, free list and qk list-> happen on first malloc calling
    if(heapEnd==heapStart){
        int init_status=init_heap();
        if(init_status==0){
            return NULL;
        }
    }

    //determine the size by adding the header

    size_t required_block_size=find_required_block_size(size);

    void *malloc_ptr=NULL;
    malloc_ptr = find_qk_list_memory(required_block_size);
    if(malloc_ptr!=NULL){
        //found in quick list
        return malloc_ptr;
    }
    //if not->
    //search free list
    //find the index of the size in free list
    malloc_ptr = find_free_list_memory(required_block_size);
    //sf_show_heap();
    //printf("required block size is %ld\n",required_block_size);
    if(malloc_ptr!=NULL){
        //found in free-list
        return malloc_ptr;
    }
    //if not again, then
    //add new page
    //printf("first show heap\n");
    //sf_show_heap();
    void *newPage=sf_mem_grow();
    //new Page should be a pointer for success
    while(newPage!=NULL){
        //sf_show_heap();
        //find the old epilogue
        sf_block *old_epilogue=newPage-EPILOGUE_SIZE;

        //set the new epilogue first
        // which is size 0 and this alloc to 1
        //printf("mem end is %p\n",sf_mem_end());
        sf_block *new_epilogue=sf_mem_end()-8;
        new_epilogue->header=(0| THIS_BLOCK_ALLOCATED);

        //check if old epilogue prv alloc is 1 or not
        if( ((old_epilogue->header) & 0x00000002) == 0x00000002){
            //no need to coalsce with before
            //find the location of new free blk
            sf_block *new_free_blk= newPage-8;

            //set its header and footer
            new_free_blk->header= 4096|PREV_BLOCK_ALLOCATED;
            sf_footer *new_free_block_footer=sf_mem_end()-EPILOGUE_SIZE-FOOTER_SIZE;
            *new_free_block_footer= new_free_blk->header;
            place_free_block_to_free_list(new_free_blk);

        }
        else{
            //need to coalsce with previous block , subtract footer size and old epilog size
            sf_footer *prev_block_footer= newPage-8-8;
            //printf("addr of new_free_block %p \n",prev_block_footer);
            //find the prev block size
            size_t prev_block_size= *prev_block_footer & 0xFFFFFFFFFFFFFFF8;
            //printf("size is : %ld \n", prev_block_size);
            size_t prev_block_prev_alloc_value= *prev_block_footer & 0x00000002;
            //locate the addr of prev block
            sf_block *new_free_block=newPage-prev_block_size-8;
            //printf("addr of new_free_block %p \n",new_free_block);
            //sf_show_heap();
            new_free_block->header= ((4096+prev_block_size) | prev_block_prev_alloc_value);
            sf_footer *new_free_block_footer= sf_mem_end()-EPILOGUE_SIZE-FOOTER_SIZE;
            *new_free_block_footer= new_free_block->header;
            remove_from_free_list(new_free_block);
            place_free_block_to_free_list(new_free_block);
            //printf("ok here2\n");
            //sf_show_heap();
        }
        //try to find it again
        malloc_ptr = find_free_list_memory(required_block_size);
        //sf_show_heap();
        if(malloc_ptr!=NULL){
            //found in free-list
            return malloc_ptr;
        }
        //not found,
        //add new page again
        newPage=sf_mem_grow();
    }
    //sf_show_heap();

    //add new page failed, so
    sf_errno=ENOMEM;
    //abort();
    return NULL;
}

void sf_free(void *pp) {
    // TO BE IMPLEMENTED
    //check any invalid pointers:
    // The pointer is NULL.
    if (pp== NULL){
        abort();
    }
    // The pointer is not 8-byte aligned.
    if ((uintptr_t)&pp % 8 != 0){
        abort();
    }
    // The block size is less than the minimum block size of 32.
    //find the header of pp
    sf_block *pp_block=(void*)pp-8;
    size_t pp_block_size=pp_block->header & 0xFFFFFFFFFFFFFFF8;
    if(pp_block_size<32){
        abort();
    }
    // The block size is not a multiple of 8
    if(pp_block_size%8!=0){
        abort();
    }
    // The header of the block is before the start of the first block of the heap,
    void* pp_block_addr=(void*)pp-8;
    if (pp_block_addr<sf_mem_start()){
        abort();
    }
    // or the footer of the block is after the end of the last block in the heap.
    void* pp_block_footer_addr=(void*)pp-8+pp_block_size-8;
    if(pp_block_footer_addr>sf_mem_end()){
        abort();
    }

    // The allocated bit in the header is 0.
    if ( (pp_block->header & THIS_BLOCK_ALLOCATED) != THIS_BLOCK_ALLOCATED ){
        abort();
    }
    // The in quick list bit in the header is 1.
    if ( (pp_block->header & IN_QUICK_LIST) == IN_QUICK_LIST){
        abort();
    }
    // The prev_alloc field in the header is 0, indicating that the previous
    // block is free, but the alloc field of the previous block header is not 0.
    //find the prv footer->
    sf_footer *footer=(void*)pp_block-8;
    if ( (pp_block->header & PREV_BLOCK_ALLOCATED) != PREV_BLOCK_ALLOCATED && (*footer & THIS_BLOCK_ALLOCATED) == THIS_BLOCK_ALLOCATED ){
        abort();
    }
    int flag=check_size_matches_quick(pp_block_size);
    if(flag==1){
        //put into quick list
        int flag1=insert_into_quick_list(pp_block,pp_block_size);
        if(flag1==1){
            //insert success
        }
        else{
            //flush the list, and call insert again
            flush_quick_list(pp_block_size);
            insert_into_quick_list(pp_block,pp_block_size);
        }
    }
    else{
        //put into free list
        //find the index to put in free list
        //coalesce with adjacent block
        coalsce_with_adjacent(pp_block);
    }
    //sf_show_heap();
}

void *sf_realloc(void *pp, size_t rsize) {
    // TO BE IMPLEMENTED
    //check any invalid pointers:
    // The pointer is NULL.
    if (pp== NULL){
        abort();
    }
    // The pointer is not 8-byte aligned.
    if ((uintptr_t)&pp % 8 != 0){
        abort();
    }
    // The block size is less than the minimum block size of 32.
    //find the header of pp
    sf_block *pp_block=(void*)pp-8;
    size_t pp_block_size=pp_block->header & 0xFFFFFFFFFFFFFFF8;
    if(pp_block_size<32){
        abort();
    }
    // The block size is not a multiple of 8
    if(pp_block_size%8!=0){
        abort();
    }
    // The header of the block is before the start of the first block of the heap,
    void* pp_block_addr=(void*)pp-8;
    if (pp_block_addr<sf_mem_start()){
        abort();
    }
    // or the footer of the block is after the end of the last block in the heap.
    void* pp_block_footer_addr=(void*)pp-8+pp_block_size-8;
    if(pp_block_footer_addr>sf_mem_end()){
        abort();
    }

    // The allocated bit in the header is 0.
    if ( (pp_block->header & THIS_BLOCK_ALLOCATED) != THIS_BLOCK_ALLOCATED ){
        abort();
    }
    // The in quick list bit in the header is 1.
    if ( (pp_block->header & IN_QUICK_LIST) == IN_QUICK_LIST){
        abort();
    }
    // The prev_alloc field in the header is 0, indicating that the previous
    // block is free, but the alloc field of the previous block header is not 0.
    //find the prv footer->
    sf_footer *footer=(void*)pp_block-8;
    if ( (pp_block->header & PREV_BLOCK_ALLOCATED) != PREV_BLOCK_ALLOCATED && (*footer & THIS_BLOCK_ALLOCATED) == THIS_BLOCK_ALLOCATED ){
        abort();
    }
    //valid but size is 0
    if(rsize==0){
        sf_free(pp);
        return NULL;
    }
    //after verify parameter
    //reallocating to a larger size
    size_t required_size=find_required_block_size(rsize);
    if(required_size>pp_block_size){
        sf_block *new_block=sf_malloc(rsize);
        if(new_block==NULL){
            return NULL;
        }
        memcpy(new_block,pp_block,pp_block_size);
        sf_free(pp);
        return new_block;
    }
    else{
        //reallocate to smaller size
        //check if splint will occur

        if ((pp_block_size-required_size) <=32){
            //do not split
            //update header and return same block
            //sf_show_heap();
            return (void*)pp_block+8;
        }
        else{
            //split it
            //
            //find the remaining size header->
            //remove the orig block
            remove_from_free_list(pp_block);
            sf_block * left_over_block=  (void*)pp_block+required_size;
            //update its size and prv alloc to 1
            left_over_block->header= ((pp_block_size-required_size)| PREV_BLOCK_ALLOCATED);
            //find its footer and update it
            sf_footer *left_over_block_footer= (void*)left_over_block+(pp_block_size-required_size)-8;
            *left_over_block_footer=left_over_block->header;

            //change the size and save the last 3 bits
            //update header and footer for remaining block
            size_t temp =pp_block->header & 0x00000007;
            //set the footer and header for this new allocated block
            sf_block *allocated_block=(void*)pp_block;
            //printf("addr of allocaed block: %p",allocated_block);
            allocated_block->header= ((required_size) | temp) | THIS_BLOCK_ALLOCATED;
            //set to alloc
            //memcpy(allocated_block,pp_block,required_size);
            coalsce_with_adjacent(left_over_block);
            return (void*)allocated_block+8;
        }
    }
    abort();
}

void *sf_memalign(size_t size, size_t align) {
    // TO BE IMPLEMENTED
    // align need to be greater than 8 and power of 2
    //
    if(align>=8 && (align & (align - 1)) == 0){
        size_t large_size=size+align+MINIMUM_SIZE+FOOTER_SIZE;
        void* large_block_payload= sf_malloc(large_size);

        //track the head of this this large block
        sf_block * large_block=(void*)large_block_payload-8;
        //size_t large_block_header= large_block->header;
        //largeblock point to the addr
        while((size_t)(void*)large_block_payload % align !=0){
            //need to free 1
            large_block_payload=large_block_payload+align;
        }
        //now large_block_payload is aligned
        sf_block * new_block=(void*)large_block_payload -8;

        //free the block
        size_t difference=new_block-large_block;
        size_t large_block_last_three_bits= large_block->header & 0x00000007;
        large_block->header= difference|large_block_last_three_bits;
        sf_free((void*)large_block);

        sf_footer* past_footer=(void*)new_block-8;
        size_t prv_temp= *past_footer & THIS_BLOCK_ALLOCATED;
        //find the required of this block
        size_t needed_size=find_required_block_size(size);
        new_block->header= (needed_size | THIS_BLOCK_ALLOCATED);
        if(prv_temp==THIS_BLOCK_ALLOCATED){
            new_block->header=new_block->header|PREV_BLOCK_ALLOCATED;
        }

        size_t prv_temp2=large_size-difference;

        size_t prv_temp3=prv_temp2-needed_size;

        sf_block * free2=(void*)new_block+needed_size;

        free2->header=(prv_temp3|PREV_BLOCK_ALLOCATED)|THIS_BLOCK_ALLOCATED;
        sf_free((void*)free2);

        return (void*) new_block +8;
}
else{
    sf_errno=EINVAL;
    return NULL;
}
    abort();
}

