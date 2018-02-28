/*************************************************************************
**************************************************************************
*                             ROUTER
*                 UM/POD : Password Of Day (POD)
*
*            Copyright (C) 2011 Hitron Technologies Inc.
*                        All Rights Reserved.
**************************************************************************
*  Filename    : um_pod.h
*  Description : POD definition
**************************************************************************
*/

#ifndef _UM_POD_H_
#define _UM_POD_H_

/*************************************************************************
                            * INCLUDE FILES *
**************************************************************************
*/
#if defined(CONFIG_UM_POD_MODULE_HITRON)
#include "um_pod_hitron.h"
#else
#error "You included POD, but no POD module is selected!"
#endif

/*************************************************************************
                            * EXTERNS *
**************************************************************************
*/

/*************************************************************************
                            * DEFINES *
**************************************************************************
*/
#if defined(CONFIG_UM_POD_MODULE_HITRON)
/* TODO */
#define UM_POD_SEED_LEN (HITRON_POD_SEED_ENC_LEN + 1)
#define UM_POD_DATE_LEN (HITRON_POD_DATE_LEN + 1)

#endif

#define UM_POD_PAM_CONFIG_PATH  "/var/pam_pod.conf"
/*************************************************************************
                            * DATA TYPES *
**************************************************************************
*/
typedef struct {
    HRM_BOOL   enable;
    HRM_CHAR   Seed[UM_POD_SEED_LEN];
    HRM_CHAR   Date[UM_POD_DATE_LEN];
    HRM_BOOL   bSeedEncrypt;
} UM_AUTH_POD;

/*************************************************************************
                            * GLOBAL VARIABLES *
**************************************************************************
*/

/*************************************************************************
                            * MACRO *
**************************************************************************
*/
#if defined(CONFIG_UM_POD_MODULE_HITRON)
/* TODO */
#define UMPOD_DecryptSeed(seed)         \
                              PodDecryptSeed( seed);
#define UMPOD_SinglePass(seed, date)    \
                              HitronPodGenerate( seed, date );

#endif
/*************************************************************************
                            * FUNCTION PROTOTYPES *
**************************************************************************
*/
#ifdef CONFIG_UM_POD_ENABLE
/*-----------------------------------------------------------------------
*  Name   : HRM_INT32 UM_PodAuthenticate (const HRM_CHAR    *password,
*                             const UM_AUTH_POD *pod)
*  Brief  : Do the Pod authentication
*  Params : seed - POD Seed
*           date - the date of the day, use "devdate" for current date in device
*           b_encrypt - whether the seed is encrypted
*  Return : 0 - Authenticate Success
*           -1 - Authenticate Failed
*------------------------------------------------------------------------
*/
HRM_INT32 UM_PodAuthenticate (const HRM_CHAR    *password,
                                UM_AUTH_POD *pod);
#endif

#endif /* _UM_POD_H_ */


