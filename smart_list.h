#ifndef _SMART_LIST_H_
#define _SMART_LIST_H_
/***********************************************************
smart list util

developed by wang hai ou.
http://www.bloomsource.org/

this code is free, you can use it for any perpose.
any bug or question , mail to whotnt@126.com
************************************************************/

typedef void  (*sl_iterator_proc)( void* item );
typedef int   (*sl_data_comp)( void* data, void* item );
typedef void  (*sl_item_proc)( void* data, void* item );

typedef struct{
    void* head;
    void* tail;
    
    int   count;
    int   next_offset;
    int   prev_offset;
    
}smart_list;



#ifdef __cplusplus
extern "C"{
#endif


int smart_list_init( smart_list* list, int next_offset, int prev_offset );

int smart_list_push_back( smart_list* list, void* item );

int smart_list_push_front( smart_list* list, void* item );

void* smart_list_pop_back( smart_list* list );

void* smart_list_pop_front( smart_list* list );

int smart_list_iterate( smart_list* list, sl_iterator_proc proc );

int smart_list_riterate( smart_list* list, sl_iterator_proc proc );

void* smart_list_delete_item( smart_list* list, void* item );

int smart_list_delete_by_data( smart_list* list, void* data, sl_data_comp cmp, sl_item_proc proc );

int smart_list_delete_by_idx( smart_list* list, int index, sl_iterator_proc proc );

int smart_list_find( smart_list* list, void* data, sl_data_comp cmp, sl_item_proc proc );

// return 1 when empty , 0 when not empty
int smart_list_empty( smart_list* list );

int smart_list_count( smart_list* list );

//return the item by index, index start with 0
void* smart_list_item_by_index( smart_list* list, int index );

#ifdef __cplusplus
}
#endif

#endif
