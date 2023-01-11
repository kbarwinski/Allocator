#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include "heap.h"

#define PAGE_SIZE       4096    // Długość strony w bajtach
#define PAGE_FENCE      1       // Liczba stron na jeden płotek
#define PAGES_AVAILABLE 16384   // Liczba stron dostępnych dla sterty
#define PAGES_TOTAL     (PAGES_AVAILABLE + 2 * PAGE_FENCE)

#define FENCE_VALUE 256

// Makro zaokrągla adres bajta __addr do adresu bazowego następnej strony
#define ROUND_TO_NEXT_PAGE(__addr) (((__addr) & ~(PAGE_SIZE - 1)) + PAGE_SIZE * !!((__addr) & (PAGE_SIZE - 1)))

#define IS_ALIGNED_TO_PAGE(__addr)(((intptr_t)__addr & (intptr_t)(PAGE_SIZE - 1)) == 0)


struct heap_t {
    uint8_t lfence[PAGE_SIZE];
    uint8_t rfence[PAGE_SIZE];
    intptr_t first_fence;
    intptr_t current_page;
    intptr_t last_fence;
    unsigned long reserved_pages;
};

struct block_t{
    uint32_t checksum;
    intptr_t fence_left;
    intptr_t fence_right;
    size_t size;
    struct block_t* next;
    struct block_t* prev;
    bool isFree;
};

#define BLOCK_SIZE(x) ((x)+2*sizeof(intptr_t) + sizeof(struct block_t))

static struct heap_t heap;

void print_heap(void){
/*    struct block_t *current = (struct block_t *) heap.current_page;
    printf("ALLOCATED PAGES: %lu ",heap.reserved_pages);
    while(current!=NULL){
        printf("[FENCES SIZE:%zu, SIZE:%zu, IS FREE:%d] -> ",current->fence_right-current->fence_left-sizeof(intptr_t),current->size,current->isFree);
        current = current->next;
    }
    printf("NULL\n");*/
}

void print_block(struct block_t* block){
    printf("[FENCES SIZE:%zu, SIZE:%zu, IS FREE:%d] -> ",block->fence_right-block->fence_left-sizeof(intptr_t),block->size,block->isFree);
}

uint32_t calculate_checksum(struct block_t *block){
    uint32_t checksum=0;
    for(int i=(int)sizeof(block->checksum); i<(int)sizeof(struct block_t); i++){
        checksum+=*((uint8_t*)block + i);
    }
    return checksum;
}

void set_block_fences(struct block_t *block, void* laddress, void*raddress){
    *(long*)laddress = FENCE_VALUE;
    block->fence_left = (intptr_t)laddress;

    *(long*)raddress = FENCE_VALUE;
    block->fence_right = (intptr_t)raddress;

    block->checksum = calculate_checksum(block);
}
void* request_pages(unsigned long page_num){
    if(heap.reserved_pages + page_num > PAGES_TOTAL)
        return NULL;

    void* res;
    res = custom_sbrk(0);
    if(res == (void *)-1){
        return NULL;
    }

    res = custom_sbrk((intptr_t)(page_num*PAGE_SIZE));
    if(res == (void *)-1){
        return NULL;
    }

    heap.reserved_pages += page_num;
    return res;
}
int heap_setup(void){
    void* res;
    heap.reserved_pages = 0;

    res = request_pages(3);
    if(res==NULL)
        return -1;

    heap.first_fence = (intptr_t)res;
    memcpy((void*)heap.first_fence, heap.lfence, PAGE_SIZE);

    heap.current_page = (intptr_t)((uint8_t*)res + PAGE_SIZE);

    heap.last_fence = (intptr_t)((uint8_t*)res + 2 * PAGE_SIZE);
    memcpy((void*)heap.last_fence, heap.rfence, PAGE_SIZE);

    struct block_t *init = (struct block_t *) heap.current_page;
    init->isFree = true;
    init->size = PAGE_SIZE - sizeof(intptr_t) * 2 - sizeof(struct block_t);

    init->next = NULL;
    init->prev = NULL;

    set_block_fences(init, (uint8_t*)init + sizeof(struct block_t),
            (uint8_t*)init + PAGE_SIZE - sizeof(intptr_t));

    print_heap();
    return 0;
}

void heap_clean(void){

    custom_sbrk(-(intptr_t)(heap.reserved_pages * PAGE_SIZE));
    heap.first_fence = (intptr_t) NULL;
    heap.current_page = (intptr_t) NULL;
    heap.last_fence = (intptr_t) NULL;
    heap.reserved_pages = 0;
}

void* merge_block(struct block_t* left, struct block_t* right){
    if(right->next!=NULL){
        right->next->prev = left;
        right->next->checksum = calculate_checksum(right->next);
    }
    left->next = right->next;
    left->size += BLOCK_SIZE(right->size);
    left->isFree = true;

    set_block_fences(left,(uint8_t*)left+sizeof(struct block_t), (uint8_t*)left+ BLOCK_SIZE(left->size)-sizeof(intptr_t));

    return left;
}

void* split_block(struct block_t* to_split, size_t size, bool free1, bool free2){
    if(to_split == NULL)
        return NULL;
    //PŁOTKI USTAWIONE NA WIELKOŚĆ INNĄ NIŻ W STRUKTURZE
    if(to_split->size <= BLOCK_SIZE(size)){
    to_split->isFree = free2;
    to_split->size = size;

     set_block_fences(to_split, (uint8_t*)to_split + sizeof(struct block_t),
                     (uint8_t*)to_split + BLOCK_SIZE(to_split->size) - sizeof(intptr_t));


     return (uint8_t*)to_split + sizeof(struct block_t) + sizeof(intptr_t);
    }

    struct block_t *allocated_block = (struct block_t*)to_split;
    struct block_t *moved_split = (struct block_t*)((uint8_t*)to_split + BLOCK_SIZE(size));

    if(to_split->next!=NULL){
        to_split->next->prev = moved_split;
        to_split->next->checksum= calculate_checksum(to_split->next);
    }

    moved_split->isFree=free1;
    moved_split->size = allocated_block->size - size - sizeof(struct block_t) - 2* sizeof(intptr_t);
    moved_split->prev = allocated_block;
    moved_split->next = allocated_block->next;

    allocated_block->isFree=free2;
    allocated_block->size = size;
    allocated_block->next = moved_split;

    set_block_fences(allocated_block, (uint8_t*)allocated_block + sizeof(struct block_t),
                     (uint8_t*)allocated_block + BLOCK_SIZE(size) - sizeof(intptr_t));

    set_block_fences(moved_split, (uint8_t*)moved_split + sizeof(struct block_t),
                     (uint8_t*)moved_split + BLOCK_SIZE(moved_split->size) - sizeof(intptr_t));

    return (uint8_t*)allocated_block + sizeof(struct block_t) + sizeof(intptr_t);
}


struct block_t* find_available_block(struct block_t *head, size_t target_size){
    struct block_t *current = head;
    struct block_t *prev = NULL;
    while(current!=NULL){
        if(current->isFree == true && current->size >= target_size){
            return current;
        }
        prev = current;
        current = current->next;
    }
    return prev;
}

void* get_more_pages(struct block_t* tail, size_t size){
    if(tail->isFree==false){
        unsigned long required_pages = (BLOCK_SIZE(size) / PAGE_SIZE);
        if(BLOCK_SIZE(size) % PAGE_SIZE != 0)
            required_pages+=1;

        void* res = request_pages(required_pages);
        if(res==NULL)
            return NULL;
        heap.last_fence += (intptr_t)required_pages * PAGE_SIZE;
        memcpy((void*)heap.last_fence, heap.rfence, PAGE_SIZE);

        struct block_t* new_block = (struct block_t*)((uint8_t*)tail + BLOCK_SIZE(tail->size));
        tail->next=new_block;
        new_block->prev = tail;
        new_block->next = NULL;
        new_block->isFree = true;
        new_block->size = (required_pages * PAGE_SIZE) - sizeof(struct block_t) - 2 * sizeof(intptr_t);

        tail->checksum = calculate_checksum(tail);
        set_block_fences(new_block,(uint8_t*)new_block+sizeof(struct block_t),
                (uint8_t*)new_block + BLOCK_SIZE(new_block->size)-sizeof(intptr_t));

        return new_block;
    }
    size_t required_size = size - tail->size;
    unsigned long required_pages = (required_size / PAGE_SIZE);
    if(required_size % PAGE_SIZE != 0)
        required_pages+=1;

    void* res = request_pages(required_pages);
    if(res==NULL)
        return NULL;
    heap.last_fence += (intptr_t)required_pages * PAGE_SIZE;
    memcpy((void*)heap.last_fence, heap.rfence, PAGE_SIZE);

    tail->size += required_pages * PAGE_SIZE;
    set_block_fences(tail, (uint8_t*)tail+sizeof(struct block_t), (uint8_t*)tail + BLOCK_SIZE(tail->size) - sizeof(intptr_t));

    return tail;
}

void* heap_malloc(size_t size){
    if(size==0)
        return NULL;
    struct block_t *head = (struct block_t *) heap.current_page;

    struct block_t *found = find_available_block(head, size);

    if(found->size<size || found->isFree == false){
        found = get_more_pages(found,size);
        if(found == NULL)
            return NULL;
    }

    void*res = split_block(found,size, true, false);
    return res;
}

void* heap_calloc(size_t number, size_t size){
    void* res = heap_malloc(number * size);
    if(res==NULL)
        return NULL;
    else{
        memset(res,0,number * size);
        return res;
    }
}

void* heap_realloc(void* memblock, size_t count){
    if(heap_validate()!=0)
        return NULL;
    if(memblock==NULL)
        return heap_malloc(count);
    if(count==0){
        heap_free(memblock);
        return NULL;
    }
    int ptrtype = get_pointer_type(memblock);
    if(ptrtype != pointer_valid)
        return NULL;

    struct block_t* target = (struct block_t*)((uint8_t*)memblock - sizeof(intptr_t) - sizeof(struct block_t));

    long size_diff = target->size - count;
    if(size_diff>0){
        target->size -= size_diff;
        set_block_fences(target, (uint8_t*)target+sizeof(struct block_t),
                         (uint8_t*)target+BLOCK_SIZE(target->size)-sizeof(intptr_t));
    }
    if(size_diff<0){
        if(target->next!=NULL){
            if(target->next->isFree==true && (long)BLOCK_SIZE(target->next->size)>=-size_diff){
                //Jeżeli za blokiem pamięci, wskazywanym przez memblock, dostępny jest obszar/blok wolnej pamięci o rozmiarze większym,
                //bądź równym rozmiarowi żądanemu przez użytkownika count minus aktualny rozmiar memblock to obszar wskazywany przez memblock jest powiększany.
                merge_block(target,target->next);
                split_block(target,count,true,true);
                target->isFree=false;
                target->checksum= calculate_checksum(target);
                return memblock;
            }
            if(target->next->isFree==true && target->next->next==NULL && (long)BLOCK_SIZE(target->next->size)<-size_diff){
                //Jeżeli obszar wskazywany przez memblock jest na końcu sterty a wielkość sterty jest zbyt mała
                //na pomyślne zwiększenie wielkości bloku memblock do size bajtów, to należy poprosić system o dodatkową pamięć (patrz sbrk()))
                if(get_more_pages(target->next,-size_diff)==NULL)
                    return NULL;
                merge_block(target,target->next);
                split_block(target,count,true,true);
                target->isFree=false;
                target->checksum= calculate_checksum(target);
                return memblock;
            }
            if(target->next->isFree==false || (long)BLOCK_SIZE(target->next->size)<-size_diff){
                //Jeżeli obszar wskazywany przez memblock nie może zostać powiększony do size bajtów (bo pamięć znajdująca się w kierunku powiększania jest już zajęta)
                //to funkcja musi przydzielić nową pamięć na size bajtów w innym miejscu sterty, następnie przenieść zawartość poprzedniego bloku do nowego.
                //osierocony blok musi zostać zwolniony 😉
                void* newblock = heap_malloc(count);
                if(newblock==NULL)
                    return NULL;
                memcpy(newblock,memblock,target->size);
                heap_free(memblock);
                return newblock;
            }
        }
    }

    return memblock;
}

void heap_free(void* memblock){
    if(memblock==NULL)
        return;
    if(get_pointer_type(memblock)!=pointer_valid)
        return;

    struct block_t* to_free = (struct block_t *) ((uint8_t *) memblock - sizeof(intptr_t) - sizeof(struct block_t));

    to_free->isFree = true;

    size_t real_size;
    if(to_free->next!=NULL){
        real_size = (intptr_t)to_free->next - to_free->fence_left - 2 * sizeof(intptr_t);
    }
    else{
        real_size = heap.last_fence - to_free->fence_left - 2 * sizeof(intptr_t);
    }
    to_free->size = real_size;

    set_block_fences(to_free, (uint8_t*)to_free+sizeof(struct block_t), (uint8_t*)to_free + BLOCK_SIZE(to_free->size) - sizeof(intptr_t));

    bool check_free = true;
    while(check_free==true){
        check_free = false;
        if(to_free->prev!=NULL){
            if(to_free->prev->isFree == true){
                to_free = merge_block(to_free->prev,to_free);
                check_free =true;
            }
        }
        if(to_free->next!=NULL){
            if(to_free->next->isFree == true){
                to_free = merge_block(to_free,to_free->next);
                check_free =true;
            }
        }
    }
}
struct block_t* find_aligned_block(struct block_t *head, size_t target_size){
    struct block_t *current = head;
    struct block_t *prev = NULL;
    while(current!=NULL){
        void* memptr = (uint8_t*)current+sizeof(struct block_t)+sizeof(intptr_t);
        intptr_t memaligned = (intptr_t)ROUND_TO_NEXT_PAGE((intptr_t)memptr);
        intptr_t memoffset = memaligned - (intptr_t)memptr;
        if(current->isFree == true && current->size >= target_size+memoffset + BLOCK_SIZE(0)){
            return current;
        }
        prev = current;
        current = current->next;
    }
    return prev;
}
void* heap_malloc_aligned(size_t count){
    if(count==0)
        return NULL;
    struct block_t *head = (struct block_t *) heap.current_page;

    struct block_t *found = find_aligned_block(head, count);
    void* memptr = (uint8_t*)found+sizeof(struct block_t)+sizeof(intptr_t);
    intptr_t memaligned = (intptr_t)ROUND_TO_NEXT_PAGE((intptr_t)memptr);
    intptr_t memoffset = memaligned - (intptr_t)memptr;

    if(found->isFree == false || found->size < count+memoffset + BLOCK_SIZE(0)){
        found = get_more_pages(found, BLOCK_SIZE(count)+memoffset);
        if(found==NULL)
            return NULL;
    }

    memptr = (uint8_t*)found+sizeof(struct block_t)+sizeof(intptr_t);
    memaligned = (intptr_t)ROUND_TO_NEXT_PAGE((intptr_t)memptr);
    memoffset = memaligned - (intptr_t)memptr;

    if(memoffset > (long)BLOCK_SIZE(0)){
        split_block(found,memoffset - (long)BLOCK_SIZE(0),true,true);
        found=found->next;
    }
    else if(memoffset!=0){
        struct block_t temp = *found;
        found = (struct block_t*)((uint8_t*)found+memoffset);
        *found = temp;
        if(found->prev!=NULL){
            found->prev->next=found;
            found->prev->checksum= calculate_checksum(found->prev);
        }
        if(found->next!=NULL){
            found->next->prev=found;
            found->next->checksum= calculate_checksum(found->next);
        }
        found->size-=memoffset;
        set_block_fences(found,(uint8_t*)found+sizeof(struct block_t)+sizeof(intptr_t), (uint8_t*)found+BLOCK_SIZE(found->size)-sizeof(intptr_t));
    }

    void* res = split_block(found,count,true,false);

    return res;
}
void* heap_calloc_aligned(size_t number, size_t size){
    void* res = heap_malloc_aligned(number * size);
    if(res==NULL)
        return NULL;
    else{
        memset(res,0,number * size);
        return res;
    }
}
void* heap_realloc_aligned(void* memblock, size_t size){
if(heap_validate()!=0)
        return NULL;
    if(memblock==NULL)
        return heap_malloc_aligned(size);
    if(size==0){
        heap_free(memblock);
        return NULL;
    }
    int ptrtype = get_pointer_type(memblock);
    if(ptrtype != pointer_valid)
        return NULL;

    struct block_t* target = (struct block_t*)((uint8_t*)memblock - sizeof(intptr_t) - sizeof(struct block_t));

    intptr_t memaligned = (intptr_t)ROUND_TO_NEXT_PAGE((intptr_t)memblock);
    intptr_t memoffset = memaligned - (intptr_t)memblock;
    long size_diff = target->size - size - memoffset;
    if(size_diff>0){
        target->size -= size_diff;
        set_block_fences(target, (uint8_t*)target+sizeof(struct block_t),
                         (uint8_t*)target+BLOCK_SIZE(target->size)-sizeof(intptr_t));
    }
    if(size_diff<0){
        if(target->next!=NULL){
            if(target->next->isFree==true && (long)BLOCK_SIZE(target->next->size)>=-size_diff){
                //Jeżeli za blokiem pamięci, wskazywanym przez memblock, dostępny jest obszar/blok wolnej pamięci o rozmiarze większym,
                //bądź równym rozmiarowi żądanemu przez użytkownika count minus aktualny rozmiar memblock to obszar wskazywany przez memblock jest powiększany.
                merge_block(target,target->next);
                split_block(target,size,true,true);
                target->isFree=false;
                target->checksum= calculate_checksum(target);
                return memblock;
            }
            if(target->next->isFree==true && target->next->next==NULL && (long)BLOCK_SIZE(target->next->size)<-size_diff){
                //Jeżeli obszar wskazywany przez memblock jest na końcu sterty a wielkość sterty jest zbyt mała
                //na pomyślne zwiększenie wielkości bloku memblock do size bajtów, to należy poprosić system o dodatkową pamięć (patrz sbrk()))
                if(get_more_pages(target->next,-size_diff)==NULL)
                    return NULL;
                merge_block(target,target->next);
                split_block(target,size,true,true);
                target->isFree=false;
                target->checksum= calculate_checksum(target);
                return memblock;
            }
            if(target->next->isFree==false || (long)BLOCK_SIZE(target->next->size)<-size_diff){
                //Jeżeli obszar wskazywany przez memblock nie może zostać powiększony do size bajtów (bo pamięć znajdująca się w kierunku powiększania jest już zajęta)
                //to funkcja musi przydzielić nową pamięć na size bajtów w innym miejscu sterty, następnie przenieść zawartość poprzedniego bloku do nowego.
                //osierocony blok musi zostać zwolniony 😉
                void* newblock = heap_malloc_aligned(size);
                if(newblock==NULL)
                    return NULL;
                memcpy(newblock,memblock,target->size);
                heap_free(memblock);
                return newblock;
            }
        }
    }

    return memblock;
}

size_t heap_get_largest_used_block_size(void){
    if(heap_validate()!=0)
        return 0;
    struct block_t *current = (struct block_t*)heap.current_page;
    size_t max_size = 0;
    while(current!=NULL){
        if(current->isFree == false && current->size > max_size)
            max_size = current->size;
        current = current->next;
    }
    return max_size;
}

enum pointer_type_t get_pointer_type(const void* const pointer){
    if(pointer == NULL)
        return pointer_null;
    if(heap_validate()!=0)
        return pointer_heap_corrupted;

    struct block_t *head = (struct block_t*)heap.current_page;

    intptr_t ptr_val = (intptr_t)pointer;

    struct block_t *current = head;
    while(current!=NULL){
        intptr_t head_begin = (intptr_t)current;
        intptr_t head_end = (intptr_t)((uint8_t*)head_begin+sizeof(struct block_t)-1);
        if(ptr_val<(intptr_t)head_begin)
            return pointer_unallocated;
        if(ptr_val>=head_begin && ptr_val<=head_end)
            return pointer_control_block;

        intptr_t lfence_begin=(intptr_t)current->fence_left;
        intptr_t lfence_end=(intptr_t)((uint8_t*)lfence_begin+sizeof(intptr_t)-1);
        intptr_t rfence_begin=(intptr_t)current->fence_right;
        intptr_t rfence_end=(intptr_t)((uint8_t*)rfence_begin+sizeof(intptr_t)-1);
        if(ptr_val>=lfence_begin && ptr_val<= lfence_end){
            if(current->isFree==true)
                return pointer_unallocated;
            return pointer_inside_fences;
        }
        if(ptr_val>=rfence_begin && ptr_val<= rfence_end){
            if(current->isFree==true)
                return pointer_unallocated;
            return pointer_inside_fences;
        }

        if(current->isFree==false && ptr_val == lfence_end+1)
            return pointer_valid;
        if(ptr_val>lfence_end && ptr_val<rfence_begin){
            if(current->isFree==false)
                return pointer_inside_data_block;
            return pointer_unallocated;
        }
        current = current->next;
    }
    return pointer_unallocated;
}

int heap_validate(void){
    if(heap.reserved_pages == 0)
        return 2;
    for(int i=0; i<4096; i++){
        uint8_t l = *((uint8_t*)heap.first_fence+i);
        uint8_t r = *((uint8_t*)heap.last_fence+i);

        if(l != heap.lfence[i]){
            return 3;
        }
        if(r != heap.rfence[i]){
            return 3;
        }
    }

    struct block_t *current = (struct block_t*)heap.current_page;
    while(current!=NULL){
        if(current->checksum != calculate_checksum(current))
            return 3;

        if(*((long*)current->fence_left) != FENCE_VALUE || *((long*)current->fence_right) != FENCE_VALUE)
            return 1;
        current = current->next;
    }
    return 0;
}
