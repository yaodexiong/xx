/*************************************************************************
**************************************************************************
*                             ROUTER
*              PAM/POD : PAM POD MODULE
*
*            Copyright (C) 2011 Hitron Technologies Inc.
*                        All Rights Reserved.
**************************************************************************
*  Filename    : pam_pod.c
*  Description : pam module for pod
*
**************************************************************************
*/

#define _PAM_POD_C_

/*************************************************************************
                            * INCLUDE FILES *
**************************************************************************
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_modules.h>

#include "um_pod.h"

#include "ccsp_custom.h"
#include "ccsp_psm_helper.h"
#include <ccsp_base_api.h>
#include "ccsp_memory.h"

/*************************************************************************
                            * LOCAL DEFINES *
**************************************************************************
*/
#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#define PAM_RETURN_CHECK                                    \
    do {                                                    \
        if (retval != PAM_SUCCESS) {                        \
            *p_ret_data = retval;                           \
            pam_set_data(pamh, "pod_setcred_return",        \
                         (void *)p_ret_data, setcred_free); \
            return retval;                                  \
        }                                                   \
    } while (0)

#if 1
#define PAM_POD_DEBUG(fmt, argc...)
#else
#define PAM_POD_DEBUG(fmt, argc...) \
    fprintf(stderr, "[%s@%d] "fmt"\n", __func__, __LINE__, ##argc)
#endif

#define UMAPI_USERNAME_LENGTH_MAX 256
    
/*************************************************************************
                            * LOCAL DATA TYPES *
**************************************************************************
*/
/*************************************************************************
                            * LOCAL GLOBAL VARIABLES *
**************************************************************************
*/
static char *PodEnabled = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.X_HITRON_COM_Pod.Enable";
static char *PodSeedEcryptionEnabled = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.X_HITRON_COM_Pod.SeedEncryptionEnable";
static char *PodSeed = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.X_HITRON_COM_Pod.Seed";
static char *MsoName = "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.Users.User.1.X_HITRON_COM_Username";

ANSC_HANDLE bus_handle = NULL;
char g_Subsystem[32] = "eRT.";

/*************************************************************************
                            * LOCAL FUNCTION PROTOTYPES *
**************************************************************************
*/
static HRM_INT32 pod_converse(pam_handle_t   *pamh,
                              HRM_INT32       msg_style,
                              HRM_CHAR       *message,
                              HRM_CHAR      **password);
static void setcred_free(pam_handle_t *pamh, void *ptr, HRM_INT32 err);
static void PamPod_ConfigInfoGet(UM_AUTH_POD *p_pod, char *mso_name);


/*************************************************************************
                            * GLOBAL FUNCTIONS *
**************************************************************************
*/
static int pod_dbusInit( void )
{
    int   ret  = 0;
    char* pCfg = CCSP_MSG_BUS_CFG;
    
    if(bus_handle == NULL)
    {
        // Dbus connection init
        #ifdef DBUS_INIT_SYNC_MODE
        ret = CCSP_Message_Bus_Init_Synced(NULL,
                                           pCfg,
                                           &bus_handle,
                                           Ansc_AllocateMemory_Callback,
                                           Ansc_FreeMemory_Callback);
        #else
        ret = CCSP_Message_Bus_Init(NULL,
                                    pCfg,
                                    &bus_handle,
                                    Ansc_AllocateMemory_Callback,
                                    Ansc_FreeMemory_Callback);
        #endif /* DBUS_INIT_SYNC_MODE */
    }
   
    if (ret == -1)
    {
        // Dbus connection error
        fprintf(stderr, " DBUS connection error\n");
        bus_handle = NULL;
    }

    return ret;
}

/*-----------------------------------------------------------------------
*  Name   : HRM_INT32 pam_sm_authenticate(pam_handle_t    *pamh,
*                                         HRM_INT32        flags,
*                                         HRM_INT32        argc,
*                                         const HRM_CHAR **argv)
*  Brief  : called to authenticate a user
*  Params :
*  Return :
*------------------------------------------------------------------------
*/
PAM_EXTERN HRM_INT32 pam_sm_authenticate(pam_handle_t      *pamh,
                                         HRM_INT32          flags,
                                         HRM_INT32          argc,
                                         const HRM_CHAR   **argv)
{
    HRM_INT32        retval, *p_ret_data;
    const HRM_CHAR  *p_user;
    HRM_CHAR        *p_password;
    UM_AUTH_POD      apod;
    HRM_CHAR         msoname[UMAPI_USERNAME_LENGTH_MAX];
    
    retval      = PAM_AUTHTOK_ERR;
    p_ret_data  = NULL;
    p_user      = p_password    = NULL;
    memset(&apod, 0, sizeof(UM_AUTH_POD));
    memset(msoname, 0, sizeof(msoname));

    PamPod_ConfigInfoGet(&apod, msoname);
    p_ret_data = malloc(sizeof(HRM_INT32));
    if (p_ret_data == NULL)
        return PAM_BUF_ERR;
    
    /*
     * authentication requires we know whom the user wants to be
     */
    retval = pam_get_user(pamh, &p_user, NULL);
    PAM_RETURN_CHECK;

    if (p_user == NULL || *p_user == '\0') {

        printf("username not known\n");
        *p_ret_data = PAM_USER_UNKNOWN;
        pam_set_data(pamh,
                     "pod_setcred_return",
                     (void *)p_ret_data,
                     setcred_free);
        return PAM_USER_UNKNOWN;
    }

    /* POD only allow mso account login */
    if (strcmp(p_user, msoname) != 0) {

        printf("POD only support mso account.\n");
        *p_ret_data = PAM_IGNORE;
        pam_set_data(pamh,
                     "pod_setcred_return",
                     (void *)p_ret_data,
                     setcred_free);
        return PAM_IGNORE;
    }
    PAM_POD_DEBUG("Pod user authentication, username: %s", p_user);

    /* grab the password (if any) from the previous authentication layer */
    retval = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&p_password);
    PAM_RETURN_CHECK;

    if (p_password) {

        p_password = strdup(p_password);
    }
    if (!p_password) {

        retval = pod_converse(pamh,
                              PAM_PROMPT_ECHO_OFF,
                              "Password: ",
                              &p_password);
        PAM_RETURN_CHECK;
    }
    if (p_password && *p_password) {

        pam_set_item(pamh, PAM_AUTHTOK, p_password);
    }

    if (apod.Seed[0] == '\0' || apod.Date[0] == '\0') {

        printf("POD cfg file is invalid.\n");
        return PAM_AUTHTOK_ERR;
    }

    if ((retval = UM_PodAuthenticate(p_password, &apod)) != 0)
        retval = PAM_AUTH_ERR;

    PAM_POD_DEBUG("%s\n", pam_strerror(pamh, retval));
    return retval;
}

PAM_EXTERN HRM_INT32 pam_sm_setcred(pam_handle_t     *pamh ,
                                    HRM_INT32         flags,
                                    HRM_INT32         argc,
                                    const HRM_CHAR  **argv)
{
    HRM_INT32    retval;
    const void  *p_retval;

    retval      = PAM_SUCCESS;
    p_retval    = NULL;

    if ((pam_get_data(pamh, "pod_setcred_return", &p_retval) == PAM_SUCCESS) &&
        p_retval) {

        retval = *(const HRM_INT32 *)p_retval;
        pam_set_data(pamh,
                     "pod_setcred_return",
                     NULL,
                     NULL);
    }

    return retval;
}

/* --- account management --- */
PAM_EXTERN HRM_INT32 pam_sm_acct_mgmt(pam_handle_t       *pamh,
                                      HRM_INT32           flags,
                                      HRM_INT32           argc,
                                      const HRM_CHAR    **argv)
{
    return PAM_SUCCESS;
}

/* --- session management --- */
PAM_EXTERN HRM_INT32 pam_sm_open_session(pam_handle_t    *pamh,
                                         HRM_INT32        flags,
                                         HRM_INT32        argc,
                                         const HRM_CHAR **argv)
{
    return PAM_SUCCESS;
}

PAM_EXTERN HRM_INT32 pam_sm_close_session(pam_handle_t       *pamh,
                                          HRM_INT32           flags,
                                          HRM_INT32           argc,
                                          const HRM_CHAR    **argv)
{
    return PAM_SUCCESS;
}

/* --- password management --- */
PAM_EXTERN HRM_INT32 pam_sm_chauthtok(pam_handle_t      *pamh,
                                      HRM_INT32          flags,
                                      HRM_INT32          argc,
                                      const HRM_CHAR    **argv)
{
    return PAM_SUCCESS;
}

/* end of module definition */

#ifdef PAM_STATIC
/* static module data */
struct pam_module _pam_pod_modstruct = {
    "pam_pod",
    pam_sm_authenticate,
    pam_sm_setcred,
    pam_sm_acct_mgmt,
    pam_sm_open_session,
    pam_sm_close_session,
    pam_sm_chauthtok
};
#endif

/*************************************************************************
                            * LOCAL FUNCTIONS *
**************************************************************************
*/
/*-----------------------------------------------------------------------
*  Name   : HRM_INT32 pod_converse(pam_handle_t   *pamh,
*                                  HRM_INT32       msg_style,
*                                  HRM_CHAR       *message,
*                                  HRM_CHAR      **password)
*  Brief  : This application-defined callback is used to allow a direct
*           communication between a loaded module and the application.
*  Params :
*  Return :
*------------------------------------------------------------------------
*/
static HRM_INT32 pod_converse(pam_handle_t   *pamh,
                              HRM_INT32       msg_style,
                              HRM_CHAR       *message,
                              HRM_CHAR      **password)
{
    const struct pam_conv       *conv;
    struct pam_message           resp_msg;
    const struct pam_message    *msg[1];
    struct pam_response         *resp;
    HRM_INT32                    retval;

    resp                = NULL;
    resp_msg.msg_style  = msg_style;
    resp_msg.msg        = message;
    msg[0]              = &resp_msg;

    /* grab the password */
    retval = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
    if (retval != PAM_SUCCESS) {

        PAM_POD_DEBUG("Get PAM_CONV ERROR: [%s]", pam_strerror(pamh, retval));
        return retval;
    }

    retval = conv->conv(1, msg, &resp, conv->appdata_ptr);
    if (retval != PAM_SUCCESS) {

        PAM_POD_DEBUG("Get PW ERROR: [%s]", pam_strerror(pamh, retval));
        return retval;
    }

    if (password) { /* assume msg.type needs a response */

        *password = resp->resp;
        free(resp);
    }

    return PAM_SUCCESS;
}

/*-----------------------------------------------------------------------
*  Name   : void setcred_free(pam_handle_t *pamh, void *ptr, HRM_INT32 err)
*  Brief  : Call back to free data
*  Params :
*  Return :
*------------------------------------------------------------------------
*/
static void setcred_free(pam_handle_t *pamh, void *ptr, HRM_INT32 err)
{
    if (ptr)
        free(ptr);
}

/*-----------------------------------------------------------------------
*  Name   : void PamPod_ConfigInfoGet(UM_AUTH_POD *p_pod, char *mso_name)
*  Brief  : Get pod config info
*  Params :
*  Return :
*------------------------------------------------------------------------
*/
static void PamPod_ConfigInfoGet(UM_AUTH_POD *p_pod, char *mso_name)
{
    int   ret      = CCSP_SUCCESS;
    char *strValue = NULL;
    
    if (pod_dbusInit() != 0) {

        PAM_POD_DEBUG("init dbus failed!");
        return;
    }

    ret = PSM_Get_Record_Value2(bus_handle, g_Subsystem, PodEnabled, NULL, &strValue);
    if (ret == CCSP_SUCCESS)
    {
        p_pod->enable = strcmp(strValue, PSM_TRUE) == 0 ? HRM_TRUE : HRM_FALSE;
        ((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(strValue);

    }

    ret = PSM_Get_Record_Value2(bus_handle, g_Subsystem, PodSeedEcryptionEnabled, NULL, &strValue);
    if (ret == CCSP_SUCCESS)
    {
        p_pod->bSeedEncrypt  = strcmp(strValue, PSM_TRUE) == 0 ? HRM_TRUE : HRM_FALSE; 

        ((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(strValue);
    }

    ret = PSM_Get_Record_Value2(bus_handle, g_Subsystem, PodSeed, NULL, &strValue);
    if (ret == CCSP_SUCCESS)
    {
        strncpy(p_pod->Seed, strValue, sizeof(p_pod->Seed) - 1);
        ((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(strValue);
    }
    
    strncpy(p_pod->Date, "devdate", sizeof(p_pod->Date) - 1);
    
    ret = PSM_Get_Record_Value2(bus_handle, g_Subsystem, MsoName, NULL, &strValue);
    if (ret == CCSP_SUCCESS)
    {
        strncpy(mso_name, strValue, UMAPI_USERNAME_LENGTH_MAX - 1);
        ((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(strValue);
    }

    if (bus_handle != NULL) {

        CCSP_Message_Bus_Exit(bus_handle);
        bus_handle = NULL;
    }

    return;
}
