/*************************************************************************
**************************************************************************
*                             ROUTER
*                 Hitron/POD : Password Of Day (POD)
*
*            Copyright (C) 2012 Hitron Technologies Inc.
*                        All Rights Reserved.
**************************************************************************
*  Filename    : um_pod_decode.c
*  Description : Wrapper for POD -d seed
**************************************************************************
*/

#define _UM_POD_DECODE_C_
/*************************************************************************
                            * INCLUDE FILES *
**************************************************************************
*/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "xyssl/base64.h"
#include "xyssl/aes.h"
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

/* AES 's key that  using in encrypt and decrypt function */
static HRM_UINT8 key[32] = {0xb5, 0xc4 ,0xba, 0xa2, 0xc6, 0xdf, 0xcb, 0xea, \
                            0xb6, 0xf8, 0xb6, 0xfe, 0xb8, 0xe7, 0xb5, 0xc4, \
                            0xca, 0xc0, 0xb2, 0xa9, 0xbb, 0xe1, 0xb9, 0xaa, \
                            0xb9, 0xfe, 0xb9, 0xdc, 0xc0, 0xed, 0xd3, 0xbf};

/*************************************************************************
                            * LOCAL FUNCTION PROTOTYPES *
**************************************************************************
*/


/*************************************************************************
                            * GLOBAL FUNCTIONS *
**************************************************************************
*/
/*-----------------------------------------------------------------------
*  Name   : HRM_CHAR * PodDecryptSeed(HRM_CHAR * seed)
*  Brief  : decrypt the seed which has been encrypted
*  Params : seed - encrypted seed value
*  Return : return a pointer which point to decrypted seed string
*  Notes  : None
*------------------------------------------------------------------------
*/
HRM_CHAR * PodDecryptSeed (HRM_CHAR * seed)
{
    HRM_INT32         len;
    HRM_UINT8         *dst ;
    HRM_INT32         keybits;
    aes_context       ctx_aes;

    if (NULL == seed || strlen(seed) != HITRON_POD_SEED_ENC_LEN) {
        
        return NULL;
    }
    len = (HITRON_POD_SEED_ENC_LEN) * 6 / 8; /* base64 rule*/
    dst = (HRM_UINT8 *)malloc(len);
    memset(dst, 0, len);
    keybits = sizeof(key) * 8;

    base64_decode(dst, &len, (HRM_UINT8 *)seed, HITRON_POD_SEED_ENC_LEN);
    aes_setkey_dec(&ctx_aes, key, keybits);
    memset(seed, 0, HITRON_POD_SEED_ENC_LEN + 1);
    aes_crypt_ecb(&ctx_aes, AES_DECRYPT, dst, (HRM_UINT8 *)seed);

    free(dst);
    return seed;
}
/*************************************************************************
                            * LOCAL FUNCTIONS *
**************************************************************************
*/

