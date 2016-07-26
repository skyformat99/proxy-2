#include "stdio.h"
#include "stdlib.h"
#include "smart_list.h"

int smart_list_init( smart_list* list, int next_offset, int prev_offset )
{
    list->head  = NULL;
    list->tail  = NULL;
    list->count = 0;
    list->prev_offset = prev_offset;
    list->next_offset = next_offset;
    
    return 0;
}

int smart_list_push_back( smart_list* list, void* item )
{
    void** prev;
    void** next;
    void*  prev_item;
    
    prev = item + list->prev_offset;
    next = item + list->next_offset;
    
    if( list->count == 0 )
    {
        *prev = NULL;
        *next = NULL;
        list->count++;
        list->head  = item;
        list->tail  = item;
    }
    else
    {
        prev_item = list->tail;
        *prev = list->tail;
        *next = NULL;
        list->count++;
        list->tail = item;
        
        next = prev_item + list->next_offset; /* update next of prev item */
        *next = item;
        
    }
    
    return 0;
    
}

int smart_list_push_front( smart_list* list, void* item )
{
    void** prev;
    void** next;
    void*  next_item;
    
    prev = item + list->prev_offset;
    next = item + list->next_offset;
    
    if( list->count == 0 )
    {
        *prev = NULL;
        *next = NULL;
        list->count++;
        list->head  = item;
        list->tail  = item;
    }
    else
    {
        next_item = list->head;
        
        *prev = NULL;
        *next = list->head;
        list->count++;
        list->head = item;
        
        prev = next_item + list->prev_offset; /* update prev of next item */
        *prev = item;
        
    }
    
    return 0;
}

void* smart_list_pop_back( smart_list* list )
{
    

    if( list->count == 0 )
        return NULL;
    else
        return smart_list_delete_item( list, list->tail );
    
    
}

void* smart_list_pop_front( smart_list* list )
{
    if( list->count == 0 )
        return NULL;
    else
        return smart_list_delete_item( list, list->head );
    
    
}

void* smart_list_delete_item( smart_list* list, void* item )
{
    void* prev_item;
    void* next_item;
    void** prev;
    void** next;
    
    prev = item + list->prev_offset;
    next = item + list->next_offset;
    
    prev_item = *prev;
    next_item = *next;
    
    
    if( prev_item == NULL )
    {
        list->head = next_item;
    }
    else
    {
        next = prev_item + list->next_offset;  /* update next pointer of prvious item */
        *next = next_item;
    }
    
    if( next_item == NULL )
    {
        list->tail = prev_item;
    }
    else
    {
        prev = next_item + list->prev_offset; /* update prev pointer of next item */
        *prev = prev_item;
    }
    
    list->count--;
    
    return item;
    
}

int smart_list_iterate( smart_list* list, sl_iterator_proc proc )
{
    void* item;
    void** next;
    
    item = list->head;
    while( item )
    {
        next = item + list->next_offset;
        proc( item );
        
        item = *next;
    }
    
    return 0;
    
}

int smart_list_riterate( smart_list* list, sl_iterator_proc proc )
{
    void*  item;
    void** prev;
    
    item = list->tail;
    while( item )
    {
        prev = item + list->prev_offset;
        proc( item );
        
        item = *prev;
    }
    
    return 0;

}

int smart_list_delete_by_data( smart_list* list, void* data, sl_data_comp cmp, sl_item_proc proc )
{
    void* item;
    void* next_item;
    void** next;
    int rc;
    
    item = list->head;
    while( item )
    {
        next = item + list->next_offset;
        next_item = *next;
        rc = cmp( data, item );
        if( rc == 0 )
        {
            if( proc )
                proc( data, item );
            smart_list_delete_item( list, item );
        }
        

        
        item = next_item;
    }
    
    return 0;
    
}

int smart_list_find( smart_list* list, void* data, sl_data_comp cmp, sl_item_proc proc )
{
    void* item;
    void* next_item;
    void** next;
    
    item = list->head;
    while( item )
    {
        next = item + list->next_offset;
        next_item = *next;
        if( cmp( data, item ) == 0 )
            proc( data, item );
        
        item = next_item;
    }
    
    return 0;
    
}

int  smart_list_empty( smart_list* list )
{
    return list->count == 0 ? 1 : 0;
    
}


int smart_list_count( smart_list* list )
{
    return list->count;
}

void* smart_list_item_by_index( smart_list* list, int index )
{
    int idx =0;
    
    void* item;
    void** next;
    
    if( index < 0 || index > list->count-1 )
        return NULL;
        
    item = list->head;
    while( item )
    {
        if( idx == index )
            break;
        
        next = item + list->next_offset;
        item = *next;
        idx++;
    }
    
    return item;
}

