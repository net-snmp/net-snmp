/*
 * netsnmp_data_list.h
 *
 * $Id$
 *
 * External definitions for functions and variables in netsnmp_data_list.c.
 */

#ifndef DATA_LIST_H
#define DATA_LIST_H

#ifdef __cplusplus
extern          "C" {
#endif

#include <net-snmp/library/snmp_impl.h>
#include <net-snmp/library/tools.h>

    typedef void    (Netsnmp_Free_List_Data) (void *);
    typedef int     (Netsnmp_Save_List_Data) (char *buf, size_t buf_len, void *);
    typedef void *  (Netsnmp_Read_List_Data) (char *buf, size_t buf_len);

    typedef struct netsnmp_data_list_s {
        struct netsnmp_data_list_s *next;
        char           *name;
        void           *data;   /* The pointer to the data passed on. */
        Netsnmp_Free_List_Data *free_func;      /* must know how to free netsnmp_data_list->data */
    } netsnmp_data_list;

    typedef struct netsnmp_data_list_saveinfo_s {
       netsnmp_data_list **datalist;
       const char *type;
       const char *token;
       Netsnmp_Save_List_Data *data_list_save_ptr;
       Netsnmp_Read_List_Data *data_list_read_ptr;
       Netsnmp_Free_List_Data *data_list_free_ptr;
    } netsnmp_data_list_saveinfo;

    NETSNMP_INLINE netsnmp_data_list * 
      netsnmp_create_data_list(const char *, void *, Netsnmp_Free_List_Data* );
    void            netsnmp_data_list_add_node(netsnmp_data_list **head,
                                               netsnmp_data_list *node);
    netsnmp_data_list *
      netsnmp_data_list_add_data(netsnmp_data_list **head,
                                 const char *name, void *data,
                                 Netsnmp_Free_List_Data * beer);
    void           *netsnmp_get_list_data(netsnmp_data_list *head,
                                          const char *node);
    void            netsnmp_free_list_data(netsnmp_data_list *head);    /* single */
    void            netsnmp_free_all_list_data(netsnmp_data_list *head);        /* multiple */
    int             netsnmp_remove_list_node(netsnmp_data_list **realhead,
                                             const char *name);
    NETSNMP_INLINE netsnmp_data_list *
    netsnmp_get_list_node(netsnmp_data_list *head,
                          const char *name);

    /** depreciated: use netsnmp_data_list_add_node() */
    void            netsnmp_add_list_data(netsnmp_data_list **head,
                                          netsnmp_data_list *node);


    void
    netsnmp_register_save_list(netsnmp_data_list **datalist,
                               const char *type, const char *token,
                               Netsnmp_Save_List_Data *data_list_save_ptr,
                               Netsnmp_Read_List_Data *data_list_read_ptr,
                               Netsnmp_Free_List_Data *data_list_free_ptr);
    int
    netsnmp_save_all_data(netsnmp_data_list *head,
                          const char *type, const char *token,
                          Netsnmp_Save_List_Data * data_list_save_ptr);
    SNMPCallback netsnmp_save_all_data_callback;
    void netsnmp_read_data_callback(const char *token, char *line);
#ifdef __cplusplus
}
#endif
#endif
