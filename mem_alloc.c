#include "mem_alloc.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "mem_alloc_types.h"

/* memory */

char memory[MEMORY_SIZE];

/* Pointer to the first free block in the memory */
mem_free_block_t *first_free; 

/* Size of metadata = 24 bytes */
int BLOCK_SIZE = sizeof(mem_free_block_t);


#define ULONG(x)((long unsigned int)(x))
#define max(x,y) (x>y?x:y)

#if defined(FIRST_FIT)

char *memory_alloc(int size){
    char *ptr;																	//ptr of the block to be returned
    mem_free_block_t *current, *free_meta;										//current => for traversing free list
																				//free_meta => new free block created when old free block is split
	mem_used_block_t *used_meta; 												//used_meta => block allocated to user
    for(current = first_free; current != NULL; current = current->next){ 		//traversing the free list to find first block that fits
    	if(current->size >= size){
    		ptr = (char*)((long unsigned int)current + BLOCK_SIZE);				//ptr to be returned point to address excluding metadata
    		if(current->size - size < BLOCK_SIZE){
    			/* Donot split block remove block from free list */
    			//if it is the first block
    			if(current == first_free){										//update first_free to point to next free block
    				first_free = current->next;
    				first_free->prev = NULL;
    				current->next = NULL;
    				current->prev = NULL;
    				break;
    			}
    			else{	// disconnect the current block from the list
    				(current->prev)->next = current->next;
    				(current->next)->prev = current->prev;
    				current->next = NULL;
    				current->prev = NULL;    				
    			}
    		}
    		else{
    			//split block
    			//create new free block
    			free_meta = (mem_free_block_t *)((long unsigned int)current + BLOCK_SIZE + size);
    			free_meta->prev = current->prev;								//connect new free block to free_list
    			free_meta->next = current->next;
    			free_meta->size = current->size - size - BLOCK_SIZE;
				if(current->prev != NULL){
					(current->prev)->next = free_meta;
				}
					
				if(current->next !=NULL){
					(current->next)->prev = free_meta;}
					
    			//if it is the first block change first free
    			if(current == first_free){
    				free_meta->prev = NULL;
    				first_free = free_meta;
    			}
    			//create used block
    			used_meta = (mem_used_block_t *)((long unsigned int)current);
    			used_meta->size = size;
    			used_meta->next = NULL;				//disconecting the used block from the list
    			used_meta->prev = NULL;
    			
    		}
    		break;									//once a block is allocated exit the FOR loop
    	}
		
    }
   if(current == NULL){								//if no free block available of desired size, print Error and exit									
   		print_error_alloc(size);
   		exit(-1); 
   }
   print_alloc_info(ptr,size);
   return (ptr);
}
#elif defined(BEST_FIT)

char *memory_alloc(int size){
    char *ptr;
    mem_free_block_t *current, *free_meta;
	mem_used_block_t *used_meta; 
	unsigned int min = MEMORY_SIZE;					//to find the minimum difference in sizes between blocks 		
	//finding the block which fits the best
	for(current = first_free; current != NULL; current = current->next){
		if(current->size - size < min){
			min = current->size - size;
			ptr = (char*)((long unsigned int)current + BLOCK_SIZE);
		}
	}
    if(ptr == NULL){								//if no free block available of desired size, print Error and exit
    	print_error_alloc(size);
    	exit(-1);
    }
	current = (mem_free_block_t *)((long unsigned int)ptr - BLOCK_SIZE);			// address of free block to be allocated

	/* similar to first fit, (deciding whether a free block should be split or not) */
	if(current->size - size < BLOCK_SIZE){
		//Donot split block; remove block from free list
		//if it is the first block
		if(current == first_free){
			first_free = current->next;
			first_free->prev = NULL;
			current->next = NULL;
			current->prev = NULL;
		}
		else{	// disconnect the current block from the list
			(current->prev)->next = current->next;
			(current->next)->prev = current->prev;
			current->next = NULL;
			current->prev = NULL;    				
		}
	}
	else{
		//split block
		//create new free block
		free_meta = (mem_free_block_t *)((long unsigned int)current + BLOCK_SIZE + size);
		free_meta->prev = current->prev;
		free_meta->next = current->next;
		free_meta->size = current->size - size - BLOCK_SIZE;
		if(current->prev != NULL){
			(current->prev)->next = free_meta;
		}
			
		if(current->next !=NULL){
			(current->next)->prev = free_meta;}
			
		//if it is the first block change first free
		if(current == first_free){
			free_meta->prev = NULL;
			first_free = free_meta;
		}
		//create used block
		used_meta = (mem_used_block_t *)((long unsigned int)current);
		used_meta->size = size;
		used_meta->next = NULL;				//disconecting the used block from the list
		used_meta->prev = NULL;
		
	}

   print_alloc_info(ptr,size);
   return (ptr);
}

#elif defined(WORST_FIT)

char *memory_alloc(int size){
    char *ptr;
    mem_free_block_t *current, *free_meta;
	mem_used_block_t *used_meta; 
	int max = 0;																	//to find the maximum difference in sizes between blocks 		
	//finding the block which fits the worst
	for(current = first_free; current != NULL; current = current->next){
		if(current->size - size > max){
			max = current->size - size;
			ptr = (char*)((long unsigned int)current + BLOCK_SIZE);
		}
	}
    if(ptr == NULL){																//if no free block found, print error and exit
    	print_error_alloc(size);
    	exit(-1);
    }
	current = (mem_free_block_t *)((long unsigned int)ptr - BLOCK_SIZE);			// address of free block to be allocated
	
	/* similar to first fit, (deciding whether a free block should be split or not) */	
	if(current->size - size < BLOCK_SIZE){
		//Donot split block; remove block from free list
		//if it is the first block
		if(current == first_free){
			first_free = current->next;
			first_free->prev = NULL;
			current->next = NULL;
			current->prev = NULL;
		}
		else{	// disconnect the current block from the list
			(current->prev)->next = current->next;
			(current->next)->prev = current->prev;
			current->next = NULL;
			current->prev = NULL;    				
		}
	}
	else{
		//split block
		//create new free block
		free_meta = (mem_free_block_t *)((long unsigned int)current + BLOCK_SIZE + size);
		free_meta->prev = current->prev;
		free_meta->next = current->next;
		free_meta->size = current->size - size - BLOCK_SIZE;
		if(current->prev != NULL){
			(current->prev)->next = free_meta;
		}
			
		if(current->next !=NULL){
			(current->next)->prev = free_meta;}
			
		//if it is the first block change first free
		if(current == first_free){
			free_meta->prev = NULL;
			first_free = free_meta;
		}
		//create used block
		used_meta = (mem_used_block_t *)((long unsigned int)current);
		used_meta->size = size;
		used_meta->next = NULL;				//disconecting the used block from the list
		used_meta->prev = NULL;
		
	}

   print_alloc_info(ptr,size);
   return (ptr);
}

#endif

void run_at_exit(void)
{
    /* function called when the programs exits */
    /* To be used to display memory leaks informations */
    
    mem_free_block_t *current;
    mem_used_block_t *used;
    int flag =0;
    if(first_free->size == MEMORY_SIZE - BLOCK_SIZE){							//checking if all the blocks are freed
        printf("No Leaks\n");
    }
    else{
        printf("\n\nMemory leaks : Following blocks not freed\n");
        if(first_free != memory){												//Checking if there are used blocks before first_free
            used = memory;
            while((long unsigned int)used != (long unsigned int)first_free){	//Printing used blocks till first_free
/* ========================= Safety checks ================================= */
            	if(used->size > MEMORY_SIZE){									//Checking if current used block has weird size
            		printf("metadata corrupted\n");
            		exit(0);
            	}
/* ========================================================================= */
                printf("Used : Block at address %lu of size = %d\n", (long unsigned int)(used)-(long unsigned int)(memory), used->size);
                used = (long unsigned int)used + BLOCK_SIZE + used->size;		//increment to next used block
            }
            flag = 1;															//Indicate there are used blocks before first_free
        }
        if(first_free == memory || flag ==1){									//First_free points to beginning of heap or there are used blocks before first free
            for(current = first_free; current != NULL; current = current->next){//traversing the free list and printing used blocks between the free blocks
            	used = current; 
/* ============================ Safety checks =================================*/
            	if(used->size > MEMORY_SIZE){									//Checking is current used block has weird size
            		printf("metadata corrupted\n");
            		exit(0);
            	}
/* ============================================================================= */
				/* printing the used blocks between two free blocks */
                while((long unsigned int)used + BLOCK_SIZE + used->size != current->next && current->next != NULL){
                    used = (long unsigned int)used + BLOCK_SIZE + used->size;	//points to used blocks between two free blocks
                    printf("Used: Block at address %lu of size = %d\n", (long unsigned int)(used)-(long unsigned int)(memory), used->size);
                }
            }
        }
    }
}

void memory_init(void){
    mem_free_block_t *meta = (mem_free_block_t *)memory;                //meta data location for the entire heap 
    meta->size = MEMORY_SIZE - BLOCK_SIZE;            					//size of the actual free heap that can be used, deducting size of metadata
	meta->next = NULL;
    meta->prev = NULL;
    first_free = meta;                                              	//first_free points to the metadata of the heap
   
    /* register the function that will be called when the programs exits*/
    atexit(run_at_exit);

    /* .... */
}

void memory_free(char *p){
	mem_free_block_t *current;
    mem_free_block_t *free_ptr = (mem_free_block_t*)((long unsigned int)p - BLOCK_SIZE);
/* ====================== Safety Check ======================================== */
    if(free_ptr->size > MEMORY_SIZE){									//Checking if block requested to be freed has weird size 	
		printf("Block size = %d bytes and it cannot be freed as metadata seems corrupted\n",free_ptr->size);
    	exit(-1);
    }
    for(current = first_free; current!= NULL; current = current->next){ //Checking to see if an unallocated block is requested to be freed (double free check)
		//Checking if free_ptr doesnot point to any location within a free block
        if((long unsigned int)current<= (long unsigned int)free_ptr && (long unsigned int)free_ptr< ((long unsigned int)current + BLOCK_SIZE + current->size)){
            printf("Attempt to free unallocated area\n");
            exit(0);
        }
    }
/* =============================================================================== */        
    current = first_free;
	if(p!= NULL){
		mem_free_block_t *free_ptr = (mem_free_block_t*)((long unsigned int)p - BLOCK_SIZE);			//free_ptr points to beginning of block including metadata
		print_free_info(p);

		//if only one free block
		if(current->prev == NULL && free_ptr < current){
			free_ptr->next = current;										//connect free_ptr to first_free
			current->prev = free_ptr;
			free_ptr->prev = NULL;
			first_free = free_ptr;											//update first_free to free_ptr
		}
		else{	
			while(current->next != NULL){									//traversing the free list till appropriate address to place the free block is found
		        if(free_ptr > current && free_ptr < current->next){
		            free_ptr->next = current->next;							//connect free_ptr to list and update pointers
		            free_ptr->prev = current;
		            current->next = free_ptr;
		            (free_ptr->next)->prev = free_ptr;
		            break;
		        }
		        current = current->next;
			}
		}

		//merging new free block to previous adjacent free block
		if(free_ptr->prev != NULL){
			if(((long unsigned int)free_ptr->prev + BLOCK_SIZE + (free_ptr->prev)->size) == (long unsigned int)free_ptr){ //checking if blocks are adjacent
		       (free_ptr->prev)->size = (free_ptr->prev)->size + BLOCK_SIZE + free_ptr->size;		//updating size of merged block
		       (free_ptr->prev)->next = free_ptr->next;												//updating pointers to merge the blocks
		       free_ptr = free_ptr->prev;
			}
		}
		//merging new free block to next adjacent free block
		if(free_ptr->next != NULL){
			if(((long unsigned int)free_ptr + BLOCK_SIZE + free_ptr->size) == (long unsigned int)free_ptr->next){ //checking if blocks are adjacent
		        free_ptr->size = (free_ptr->next)->size + BLOCK_SIZE + free_ptr->size;				//updating size of merged block
		        free_ptr->next = (free_ptr->next)->next;											//updating pointers to merge the blocks										
		    }
		}
	}

}


void print_alloc_info(char *addr, int size){
  if(addr){
      fprintf(stderr, "ALLOC at : %lu (%d byte(s))\n", 
              ULONG(addr - memory), size);
  }
  else{
      fprintf(stderr, "Warning, system is out of memory\n"); 
  }
}


void print_free_info(char *addr){
    if(addr){
        fprintf(stderr, "FREE  at : %lu \n", ULONG(addr - memory));
    }
    else{
        fprintf(stderr, "FREE  at : %lu \n", ULONG(0));
    }
}

void print_error_alloc(int size) 
{
    fprintf(stderr, "ALLOC error : can't allocate %d bytes\n", size);
}

void print_info(void) {
  fprintf(stderr, "Memory : [%lu %lu] (%lu bytes)\n", (long unsigned int) memory, (long unsigned int) (memory+MEMORY_SIZE), (long unsigned int) (MEMORY_SIZE));
}


void print_free_blocks(void) {
    mem_free_block_t *current; 
    fprintf(stderr, "Begin of free block list :\n"); 
    for(current = first_free; current != NULL; current = current->next)
        fprintf(stderr, "Free block at address %lu, size %u\n", ULONG((char*)current - memory), current->size);
}

char *heap_base(void) {
  return memory;
}

#ifdef MAIN
int main(int argc, char **argv){

  /* The main can be changed, it is *not* involved in tests */
  memory_init();
  print_info(); 
  print_free_blocks();

/* ============= UNCOMMENT FOLLOWING LINES TO TEST MEMORY LEAKS====================== */
/*  Case one : all blocks not free  */
/*
  char *a = memory_alloc(50);
  char *b = memory_alloc(50);
  char *c = memory_alloc(75);
  char *d = memory_alloc(50);
  char *e = memory_alloc(50);
  memory_free(b);
  memory_free(d);
*/
/* Case 2 : all blocks freed */
/*
  memory_free(a);
  memory_free(c); 
  memory_free(e); 
*/
/*=================================================================================*/



/* ============= UNCOMMENT FOLLOWING LINES TO TEST INCORRECT FREE ====================== */
/*
  char *a = memory_alloc(50);
  char *b = memory_alloc(50);
  char *c = memory_alloc(75);
  char *d = memory_alloc(50);
  char *e = memory_alloc(50);
  memory_free(b);
  memory_free(d);
  memory_free(d);
*/
/*========================================================================================*/



/* ============= UNCOMMENT FOLLOWING LINES TO TEST CORUPTION OF METADATA ====================== */
/*
  char *a = memory_alloc(100);   			//allocate memory of 100 bytes (ptr a executes the metadat
  print_free_blocks();
  a = a-24;									//modify a to make it point to metadata
  *a = 'a';									//since size of block is an integer, modify 4 bytes with 4 characters
  *(a+1) = 'b';								
  *(a+2) = 'c';
  *(a+3) = 'd';
  a = a+24;									//modify a to now point to current location as returned by memory_alloc(100)
  memory_free(a);							//Now try freeing this block of 100 bytes after corrupting its size in the metadata
*/

/*================================================================================================ */
  return EXIT_SUCCESS;
}
#endif 
