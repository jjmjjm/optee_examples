#ifndef TA_JIMMY_TEST_H
#define TA_JIMMY_TEST_H


#include "tee_internal_api.h"
#include "tee_api_defines.h"
#include "trace.h"
#include "tee_api_defines_extensions.h"


/* This UUID is generated with uuidgen
   the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html */
#define TA_JIMMY_TEST_UUID { 0x8baaf200, 0x2450, 0x11e4, \
		{ 0xab, 0xe2, 0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1c} }


#define SIZE_OF_AES256_KEY      32U
#define SIZE_OF_AES128_KEY      16U

#define SIZE_OF_AES256_IV       32U
#define SIZE_OF_AES128_IV       16U

#define SIZE_OF_AES128_BLOCK_LEN 16U
#define SIZE_OF_AES256_BLOCK_LEN 32U

/* Define the return status of each function */
#define   FAIL     -1            /* Return value when operation fail */
#define   OK        0            /* Return value when operation OK */
#define   TEE_FAIL -1
#define   TEE_ALG_INVALID 0x0000FFFF

#define TA_MY_CRYPTO_VERIFY_UUID   { 0x8baaf200, 0x2450, 0x11e4, \
		{ 0xab, 0xe2, 0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1c} }


/* Define the command index in this TA(Get Aes boot key) */
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


/* Define the debug flag */
#define DEBUG
#define TF    MSG_RAW
//#define TF    ta_debug

#define UNUSED(x) (void)(x)




/*
 *******************************************************************************
 *                STRUCTRUE DEFINITION USED ONLY BY THIS MODULE
 *******************************************************************************
*/
typedef unsigned char  UINT8;    /**< Typedef for 8bits unsigned integer  */
typedef unsigned short UINT16;   /**< Typedef for 16bits unsigned integer */
typedef uint32_t       UINT32;   /**< Typedef for 32bits unsigned integer */
typedef signed char    INT8;     /**< Typedef for 8bits signed integer    */
typedef signed short   INT16;    /**< Typedef for 16bits signed integer   */
typedef signed int     INT32;    /**< Typedef for 32bits signed integer   */
typedef char           CHAR;     /**< Typedef for char                    */
typedef uint32_t       TEE_CRYPTO_ALGORITHM_ID;



typedef struct _AesOperation
{
    CHAR* inBuf;
    CHAR* outBuf;
    CHAR* key;
    CHAR* iv;
    UINT32 dataLen;
    UINT32 keyLen;
    UINT32 ivLen;
    UINT32 algorithmId;
    TEE_OperationMode operMode;
}AesOperation;




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


extern void g_TA_Printf(CHAR* buf, UINT32 len);
extern void g_TA_Printfc(CHAR* buf, UINT32 len);
extern int g_CryptoTaAes_AesOper(AesOperation aesOper,TEE_Param params[4]);
extern int g_CryptoTaHandle_Random(uint32_t paramTypes, TEE_Param params[4]);
extern int g_CryptoTaHandle_Sha(uint32_t paramTypes, TEE_Param params[4]);
extern int g_CryptoTaHandle_Aes(uint32_t paramTypes, TEE_Param params[4]);
extern int g_CryptoTaHandle_Rsa(uint32_t paramTypes, TEE_Param params[4], UINT32 opMode, UINT32 padding);
extern int g_CryptoTaHandle_Pbkdf(uint32_t paramTypes, TEE_Param params[4]);
extern int g_CryptoTaHandle_hmac(uint32_t paramTypes, TEE_Param params[4]);
extern int g_CryptoTaHandle_base64(uint32_t paramTypes, TEE_Param params[4]);

#endif /*TA_JIMMY_TEST_H*/
