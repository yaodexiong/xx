/*************************************************************************
**************************************************************************
*                             ROUTER
*                 UM/POD : Password Of Day Authentication
*
*            Copyright (C) 2011 Hitron Technologies Inc.
*                        All Rights Reserved.
**************************************************************************
*  Filename    : um_pod.c
*  Description : Wrapper for POD implement
**************************************************************************
*/
#ifdef CONFIG_UM_POD_ENABLE

#define _UM_POD_C_

/*************************************************************************
                            * INCLUDE FILES *
**************************************************************************
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "um_pod.h"

/*************************************************************************
                            * LOCAL DEFINES *
**************************************************************************
*/
/*************************************************************************
                            * LOCAL DATA TYPES *
**************************************************************************
*/
/*************************************************************************
                            * LOCAL GLOBAL VARIABLES *
**************************************************************************
*/
/*************************************************************************
                            * LOCAL FUNCTION PROTOTYPES *
**************************************************************************
*/

/*************************************************************************
                            * GLOBAL FUNCTIONS *
**************************************************************************
*/

/*-----------------------------------------------------------------------
*  Name   : HRM_INT32 UM_PodAuthenticate (const HRM_CHAR *seed,
*                             const HRM_CHAR *date,
*                             HRM_BOOL        b_encrypt)
*  Brief  : Do the Pod authentication
*  Params : seed - POD Seed
*           date - the date of the day, use "devdate" for current date in device
*           b_encrypt - whether the seed is encrypted
*  Return : 0 - Authenticate Success
*           -1 - Authenticate Failed
*------------------------------------------------------------------------
*/
HRM_INT32 UM_PodAuthenticate (const HRM_CHAR    *password,
                                    UM_AUTH_POD *pod)
{
    HRM_CHAR *ct_seed;
    HRM_CHAR *rl_date;
    HRM_CHAR *pod_pass;
    HRM_BOOL bPass;

    ct_seed  = NULL;
    rl_date  = NULL;
    pod_pass = NULL;
    bPass    = HRM_FALSE;

    if (pod->bSeedEncrypt) {

        ct_seed = UMPOD_DecryptSeed(pod->Seed);
        if (ct_seed == NULL) {

            fprintf(stderr, "[pod]: decrypt the seed failed!\n");
            return -1;
        }
    } else {

        ct_seed = pod->Seed;
    }

    if (strcmp(pod->Date, "devdate") != 0) {

        rl_date = pod->Date;
    }

    pod_pass = UMPOD_SinglePass(ct_seed, rl_date);

    if (NULL == pod_pass) {
        fprintf(stderr, "[pod]: generate password failed\n");
        return -1;
    }

    bPass = strcmp(pod_pass, password) == 0 ? HRM_TRUE : HRM_FALSE;
    free(pod_pass);

    if (bPass == HRM_FALSE) {

        return -1;
    }

    return 0;
}

/*************************************************************************
                            * LOCAL FUNCTIONS *
**************************************************************************
*/
#endif /* CONFIG_UM_POD_ENABLE */
