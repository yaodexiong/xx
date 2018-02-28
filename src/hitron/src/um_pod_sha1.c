/*************************************************************************
**************************************************************************
*                             ROUTER
*                 Hitron/POD : Password Of Day (POD)
*
*            Copyright (C) 2012 Hitron Technologies Inc.
*                        All Rights Reserved.
**************************************************************************
*  Filename    : um_pod_sha1.c
*  Description : Wrapper for POD implement
**************************************************************************
*/
#define _UM_POD_SHA1_C_
/*************************************************************************
                            * INCLUDE FILES *
**************************************************************************
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>

#include "xyssl/sha1.h"
#include "um_pod_hitron.h"

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
*  Name   : HRM_CHAR * HitronPodGenerate ( HRM_CHAR * ct_seed, HRM_CHAR * rl_date )
*  Brief  : Generate the Pod
*  Params : ct_seed - POD Seed
*           rl_date - the date of the day
*  Return : point to pod string
*  Note   : None
*------------------------------------------------------------------------
*/
HRM_CHAR * HitronPodGenerate (HRM_CHAR * ct_seed, HRM_CHAR * rl_date)
{
    HRM_INT32     i;
    HRM_UINT8    *sha1sum ;
    HRM_UINT8    *source ;
    sha1_context  ctx_sha1;

    /* plain text: seed+pod, then: sha1(plain text) */
    #define PLAIN_TEXT_LEN_MAX (HITRON_POD_SEED_DEC_LEN_MAX+HITRON_POD_DATE_LEN)

    sha1sum = (HRM_UINT8 *)malloc((HITRON_POD_PWD_LEN + 1) * sizeof(HRM_UINT8));
    source = (HRM_UINT8 *)malloc((PLAIN_TEXT_LEN_MAX + 1) * sizeof(HRM_UINT8));
    memset(sha1sum, 0, HITRON_POD_PWD_LEN + 1);
    memset(source, 0, PLAIN_TEXT_LEN_MAX + 1);

    if (ct_seed == NULL || strlen(ct_seed) > HITRON_POD_SEED_DEC_LEN_MAX) {

        return NULL;
    }
    strcat((HRM_CHAR*)source, ct_seed);
    
    if (rl_date == NULL) {
        rl_date = (HRM_CHAR *)malloc((HITRON_POD_DATE_LEN + 1) *
                                                             sizeof(HRM_CHAR));

        time_t t = time(0);
        strftime((char *)rl_date, HITRON_POD_DATE_LEN + 1, "%Y/%m/%d",
                                                             localtime(&t));
        strcat((HRM_CHAR*)source, rl_date);
        free(rl_date);
    } else {
        strcat((HRM_CHAR*)source, rl_date);
    }
    
    sha1_starts(&ctx_sha1);
    sha1_update(&ctx_sha1, source, strlen((const HRM_CHAR *)source));
    sha1_finish(&ctx_sha1, sha1sum);

    for (i = 0; i < HITRON_POD_PWD_LEN; i++) {

    /* convert each char into common char */
        if (sha1sum[i] < 46)
            sha1sum[i] += 46;
        if (sha1sum[i] > 122)
            sha1sum[i] = sha1sum[i] / 77 + sha1sum[i] % 77 + 46;
        if (sha1sum[i] > 122) {

            if (i > 1)
                sha1sum[i] -= i;
            else
                sha1sum[i] -= 2;
        }
        if ((sha1sum[i] > 57) && (sha1sum[i] <65))
            sha1sum[i] += 7;
        if ((sha1sum[i] > 90) && (sha1sum[i]<97))
            sha1sum[i] += 6;
    }

    free(source);

    return (HRM_CHAR *)sha1sum;
}

/*************************************************************************
     * LOCAL FUNCTIONS *
**************************************************************************
*/
