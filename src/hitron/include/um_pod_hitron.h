/*************************************************************************
**************************************************************************
*                             ROUTER
*                 Hitron/POD : Password Of Day (POD)
*
*            Copyright (C) 2012 Hitron Technologies Inc.
*                        All Rights Reserved.
**************************************************************************
*  Filename    : hitron_pod.h
*  Description : generate pod
**************************************************************************
*/

#ifndef _HITRON_POD_H_
#define _HITRON_POD_H_


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
#define HITRON_POD_PWD_LEN          20 /* it's fixed for designed */
#define HITRON_POD_SEED_ENC_LEN     24 /* encrypt 24,it's fixed for designed */
#define HITRON_POD_SEED_DEC_LEN_MAX 16 /* it's limit for designed */
#define HITRON_POD_DATE_LEN         10 /* format: 2015/02/04 */

#define HITRON_POD_TRACE(fmt,args...) \
    fprintf(stderr, "POD[%d] TRACE: "fmt"\n", __LINE__, ##args)

/*************************************************************************
                            * DATA TYPES *
**************************************************************************
*/
/*************************************************************************
                            * GLOBAL VARIABLES *
**************************************************************************
*/

/*************************************************************************
                            * MACRO *
**************************************************************************
*/
/*************************************************************************
                            * FUNCTION PROTOTYPES *
**************************************************************************
*/
/*-----------------------------------------------------------------------
*  Name   : HRM_CHAR* HitronPodGenerate( HRM_CHAR *seed, HRM_CHAR *date )
*  Brief  : Do generate pod according of seed and date
*  Params : seed - POD Seed
*           date - the date of the day
*  Return : pointer to password string
*------------------------------------------------------------------------
*/
HRM_CHAR* HitronPodGenerate ( HRM_CHAR *seed, HRM_CHAR *date );

/*-----------------------------------------------------------------------
*  Name   : HRM_CHAR* PodDecryptSeed(HRM_CHAR * seed);
*  Brief  : Do decrypt the encrypted seed
*  Params : seed - POD Seed that is encrypted
*  Return : pointer to decrypted seed string
*------------------------------------------------------------------------
*/
HRM_CHAR* PodDecryptSeed (HRM_CHAR * seed);
#endif


