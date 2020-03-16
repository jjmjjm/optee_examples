#ifndef MOUDLE_CRYPTO_VERIFY_CA_H_
#define MOUDLE_CRYPTO_VERIFY_CA_H_


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include "tee_client_api.h"



#define CRYPTO_VERIFY_UUID_ID  { 0x8baaf200, 0x2450, 0x11e4, \
		{ 0xab, 0xe2, 0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1c} }


#define CRYPTO_VERIFY_TASK "CV_task"          /**< TA name of managing pay key    */


/* Define the comman ID */
#define CMD_GEN_RANDOM_OPER                   1U     /**< Command ID of using RSA algorithm to signa data */
#define CMD_SHA_OPER                          2U     /**< Command ID of using RSA algorithm to signa data */
#define CMD_AES_OPER                          3U
#define CMD_PBKDF_OPER                        4U
#define CMD_MAX_NUMBER                        5U     /**< The max command number in this TA           */ 
#define CMD_RSA_ENC_PKCS1_OPER            6U     /**< Command ID of using RSA algorithm to signa data */
#define CMD_RSA_DEC_PKCS1_OPER            7U
#define CMD_RSA_SIGN_PKCS1_OPER           8U
#define CMD_RSA_VERIFY_PKCS1_OPER         9U    
#define CMD_HMAC_OPER                          10U 
#define CMD_BASE64_OPER                 11U
#define CMD_BN_OPER                          14U 


/* Define the return value of function */
#define FAIL -1
#define OK   0



/*
 *******************************************************************************
 *                STRUCTRUE DEFINITION USED ONLY BY THIS MODULE
 *******************************************************************************
*/
/* RSA key type(1024,2048) */
typedef enum
{
    EN_KEY_1024 = 1,
    EN_KEY_2048,
    EN_KEY_INVALID
}EN_RSA_KEY_TYPE;

/* Define the type of variable */
typedef unsigned char  UINT8;    /**< Typedef for 8bits unsigned integer  */
typedef unsigned short UINT16;   /**< Typedef for 16bits unsigned integer */
typedef unsigned int   UINT32;   /**< Typedef for 32bits unsigned integer */
typedef signed char    INT8;     /**< Typedef for 8bits signed integer    */
typedef signed short   INT16;    /**< Typedef for 16bits signed integer   */
typedef signed int     INT32;    /**< Typedef for 32bits signed integer   */
typedef char           CHAR;     /**< Typedef for char                    */



/* SHA operation type */
typedef enum
{
    EN_OP_SHA1 = 1,
    EN_OP_SHA224,
    EN_OP_SHA256,
    EN_OP_SHA384,
    EN_OP_SHA512,
    EN_OP_SHA_INVALID
}EN_SHA_MODE;



/* AES operation type */
typedef enum
{
    EN_OP_AES_ENCRYPT = 1,
    EN_OP_AES_DECRYPT,
    EN_OP_AES_INVALID
}EN_AES_OPERATION_ACTION;

/* AES mode type */
typedef enum
{
    EN_MODE_CBC = 1,
    EN_MODE_ECB,
    EN_MODE_CTR,
    EN_MODE_CBC_CTS,
    EN_MODE_INVALIE
}EN_AES_MODE;


typedef struct _AesOperModeInfo
{
    EN_AES_OPERATION_ACTION active;
    EN_AES_MODE mode;
}AesOperModeInfo;


typedef struct RsaCaPara_s
{
    CHAR* m_pInput;
    CHAR* m_pOutput;
    UINT32 m_InputLen;
    UINT32 m_OutputLen;
    UINT32 cmdId;
    EN_RSA_KEY_TYPE Rsa_Elect;
}RsaCaPara;



#endif  /* MOUDLE_NAME_H*/
