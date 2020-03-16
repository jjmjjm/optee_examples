#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include "jimmy_test_ta.h"


CHAR g_Aes128Key[] = 
{
	0x2FU, 0x58U, 0x7FU, 0xF0U, 0x43U, 0x83U, 0x95U, 0x3CU,
	0x1DU, 0x44U, 0x05U, 0x2BU, 0x61U, 0x49U, 0x17U, 0xF8U
};

CHAR g_Aes128Iv[] = 
{	0x1DU, 0x44U, 0x05U, 0x2BU, 0x61U, 0x49U, 0x17U, 0xF8U,
        0x58U, 0xE0U, 0x90U, 0x43U, 0x84U, 0xA1U, 0xC1U, 0x75U
};

void g_TA_Printf(CHAR* buf, UINT32 len)
{
	UINT32 index = 0U;
	for(index = 0U; index < len; index++){
		if(index < 15U){
		}else if(0U == index%16U){
			printf("\n");
		}
		else{
		}
	
		printf("0x%02x, ", (buf[index] & 0xFFU));

	}
	printf("\n\n");
}

void g_TA_Printfc(CHAR* buf, UINT32 len)
{
	UINT32 index = 0U;
	for(index = 0U; index < len; index++){
		printf("%c", buf[index]);

	}
	printf("\n\n");
}
static void l_CryptoTaHandle_SetAes128Key(AesOperation* aesOper)
{
	aesOper->key = g_Aes128Key;
	aesOper->iv = g_Aes128Iv;
	aesOper->keyLen = 128U;
	aesOper->ivLen = 16U;
}

static void l_CryptoTaHandle_SetAesAction(AesOperation* aesOper, AesOperModeInfo modeInfo)
{
	switch(modeInfo.active){
	case EN_OP_AES_ENCRYPT:
		aesOper->operMode = TEE_MODE_ENCRYPT;
		break;
	case EN_OP_AES_DECRYPT:
		aesOper->operMode = TEE_MODE_DECRYPT;
		break;
	default:
		break;
	}

	switch(modeInfo.mode){
	case EN_MODE_CBC:
		aesOper->algorithmId= TEE_ALG_AES_CBC_NOPAD;
		break;
	case EN_MODE_ECB:
		aesOper->algorithmId = TEE_ALG_AES_ECB_NOPAD;
		break;
	case EN_MODE_CTR:
		aesOper->algorithmId = TEE_ALG_AES_CTR;
		break;
	case EN_MODE_CBC_CTS:
		aesOper->algorithmId = TEE_ALG_AES_CTS;
		break;
	default:
		break;
	}
}



int g_CryptoTaAes_AesOper(AesOperation aesOper,TEE_Param params[4])
{
	TEE_OperationHandle l_pOperation = NULL;
	TEE_ObjectHandle l_pKeyObj = NULL;
	TEE_Attribute l_pAttr;
	CHAR* l_pInbuf = aesOper.inBuf;
	CHAR* l_pOutbuf = aesOper.outBuf;
	UINT32 l_dataLen = aesOper.dataLen;
	TEE_Result l_RetVal = TEE_FAIL;
	int l_Result = FAIL;


	printf("The Aes operation information just like follow:\n");
	printf("Aes key=\n");
	g_TA_Printf(aesOper.key, aesOper.keyLen/8);
	printf("IV=\n");
	g_TA_Printf(aesOper.iv, aesOper.ivLen);
	printf("Algorith= 0x%x\n", aesOper.algorithmId);
	printf("Mode=0x%x\n", aesOper.operMode);
	printf("Raw just like follow:\n");
	g_TA_Printf(aesOper.inBuf, aesOper.dataLen);

	l_RetVal = TEE_AllocateOperation(&l_pOperation, aesOper.algorithmId, aesOper.operMode, aesOper.keyLen);
	if(TEE_SUCCESS != l_RetVal){
		l_Result = FAIL;
		goto cleanup_1;
	}

	printf("Allocate object\n");
	l_RetVal = TEE_AllocateTransientObject(TEE_TYPE_AES, aesOper.keyLen, &l_pKeyObj);
	if(TEE_SUCCESS != l_RetVal){
		l_Result = FAIL;
		goto cleanup_1;
	}   

	printf("Init attribute\n");
	TEE_InitRefAttribute(&l_pAttr, TEE_ATTR_SECRET_VALUE, aesOper.key, 16);
	l_RetVal = TEE_PopulateTransientObject(l_pKeyObj, &l_pAttr, 1);
	if(TEE_SUCCESS != l_RetVal){
		l_Result = FAIL;
		goto cleanup_1;
	}

	printf("Set key\n");
	l_RetVal = TEE_SetOperationKey(l_pOperation, l_pKeyObj);
	if(TEE_SUCCESS != l_RetVal){
		l_Result = FAIL;
		goto cleanup_2;
	}

	printf("Init cipher\n");
	TEE_CipherInit(l_pOperation, aesOper.iv, aesOper.ivLen);

	printf("Do final cipher\n");
	l_RetVal = TEE_CipherDoFinal(l_pOperation, l_pInbuf, l_dataLen, l_pOutbuf, &l_dataLen);
	if(TEE_SUCCESS != l_RetVal){
		l_Result = FAIL;
	}else{
		l_Result = OK;
	}

	printf("The aes operation out put just like follow:\n");
	params[3].value.a=aesOper.dataLen-aesOper.outBuf[l_dataLen-1];
	printf("value a is %d:\n",params[3].value.a);
	g_TA_Printf(aesOper.outBuf, params[3].value.a);
	g_TA_Printfc(aesOper.outBuf, params[3].value.a);



cleanup_2:
	TEE_FreeOperation(l_pOperation);
cleanup_1:
	return l_Result;
}

int g_CryptoTaHandle_Aes(uint32_t paramTypes, TEE_Param params[4])
{
	AesOperation l_aesOper;
	AesOperModeInfo l_pAesModeInfo;
	CHAR test[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
	UNUSED(paramTypes);

	printf("Start to do AES operation!!!!\n");
	l_pAesModeInfo.active = params[0].value.a;
	l_pAesModeInfo.mode = params[0].value.b;
	l_aesOper.inBuf = params[1].memref.buffer;
	l_aesOper.outBuf = params[2].memref.buffer;
	l_aesOper.dataLen = params[3].value.a;
	TEE_MemMove(l_aesOper.outBuf, test, sizeof(test));

	l_CryptoTaHandle_SetAes128Key(&l_aesOper);

	l_CryptoTaHandle_SetAesAction(&l_aesOper, l_pAesModeInfo);
	printf("ID: 0x%x, mode: 0x%x\n", l_aesOper.algorithmId, l_aesOper.operMode);
	
	g_CryptoTaAes_AesOper(l_aesOper, params);

	return OK;
}

TEE_Result TA_CreateEntryPoint(void)
{
	printf("Crypto verify task TA_CreateEntryPoint \n");

	return TEE_SUCCESS;
}







/** @ingroup MOUDLE_NAME_C_
 *- #Description  This function openning the session of crypto verify task.
 * @param   void
 *
 * @return     TEE_Result
 * @retval     TEE_SUCCESS
 *
 *
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t paramTypes, TEE_Param __maybe_unused params[4], 
                void __maybe_unused **sessionContext)
{
	TEE_Result ret=TEE_SUCCESS;
	printf("Crypto verify task TA_OpenSessionEntryPoint\n");

	UNUSED(paramTypes);
	UNUSED(params);
	UNUSED(sessionContext);

	return ret;
}



/** @ingroup MOUDLE_NAME_C_
 *- #Description  This function closing the seccsion of crypto verify task.
 * @param   void
 *
 * @return	 TEE_Result
 * @retval	 TEE_SUCCESS
 *
 *
 */
void TA_CloseSessionEntryPoint(void __maybe_unused *session_context)
{
	printf("Crypto verify task TA_CloseSessionEntryPoint\n");
	UNUSED(session_context);
}



/** @ingroup MOUDLE_NAME_C_
 *- #Description  This function for destroying the task of crypto verify.
 * @param   void
 *
 * @return	 TEE_Result
 * @retval	 TEE_SUCCESS
 *
 *
 */

void TA_DestroyEntryPoint(void)
{
	printf("Crypto verify task TA_DestroyEntryPoint\n");
}







/** @ingroup MOUDLE_NAME_C_
 *- #Description  This function for handling the command in crypto verify task.
 * @param   void
 *
 * @return	 TEE_Result
 * @retval	 TEE_SUCCESS
 *
 *
 */
TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *session_context,
                uint32_t cmd_id, 
                uint32_t paramTypes, TEE_Param params[4])
{
	TEE_Result l_ret = TEE_SUCCESS;
	int l_RetVal = FAIL;

	printf("CMD_ID = %d\n", cmd_id);


	switch(cmd_id){
	case CMD_AES_OPER:
		printf("Entry the aes operation!!!\n");
		l_RetVal = g_CryptoTaHandle_Aes(paramTypes, params);
		break;
	default:
		l_RetVal = FAIL;
		break;
	}

	if(FAIL == l_RetVal){
		l_ret = TEE_FAIL;
	}else{
		l_ret = TEE_SUCCESS;
	}

	return  l_ret;
}


