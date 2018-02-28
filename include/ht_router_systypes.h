/*************************************************************************
**************************************************************************
*                             ROUTER
*                 Common/Pform/System : Hitron Router Module(HRM)
*
*            Copyright (C) 2011 Hitron Technologies Inc.
*                        All Rights Reserved.
**************************************************************************
*  Filename    : ht_router_systypes.h
*  Description : Router type defines for the primitive 'C' types
*  Notes       : Generic header for global scope
**************************************************************************
*/

#ifndef _HT_ROUTER_SYSTYPES_H_
#define _HT_ROUTER_SYSTYPES_H_

/*************************************************************************
                            * INCLUDE FILES *
**************************************************************************
*/

/*************************************************************************
                            * EXTERNS *
**************************************************************************
*/

/*************************************************************************
                            * DEFINES *
**************************************************************************
*/

#ifdef CONFIG_TI_GW_SEPARATE_FS_ENABLE
#define GW_FILESYSTEM_PATH \
    CONFIG_TI_SEPARATE_FS_ROOT_NAME"/"CONFIG_TI_GW_SEPARATE_FS_NAME
#else
#define GW_FILESYSTEM_PATH ""
#endif

/*************************************************************************
                            * DATA TYPES *
**************************************************************************
*/
/* Router module Bool types */
typedef  enum{
    HRM_FALSE = 0,
    HRM_TRUE  = 1,
} HRM_BOOL;

/* Signed Integer */
typedef  signed char   HRM_INT8;
typedef  signed short  HRM_INT16;
typedef  signed int    HRM_INT32;

/* Unsigned Integer */
typedef  unsigned char   HRM_UINT8;
typedef  unsigned short  HRM_UINT16;
typedef  unsigned int    HRM_UINT32;

/* Characters & Strings */
typedef  char        HRM_CHAR;
typedef  char       *HRM_STRING;


/*************************************************************************
                            * GLOBAL VARIABLES *
**************************************************************************
*/

/*************************************************************************
                            * MACRO *
**************************************************************************
*/
#define HRM_UNALIGNED_UINT32_GET(P)   \
    (((struct { HRM_UINT32 d; } __attribute__((packed)) *)(P))->d)

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) \
    (sizeof(x) / sizeof((x)[0]))
#endif

/*************************************************************************
                            * FUNCTION PROTOTYPES *
**************************************************************************
*/

#endif /* _HT_ROUTER_SYSTYPES_H_ */
