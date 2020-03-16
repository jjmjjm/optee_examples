#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <tee_client_api.h>
#include "aes_test.h"



static int g_TaskInitFlag = -1;
TEEC_UUID svc_id = CRYPTO_VERIFY_UUID_ID;
TEEC_Context g_TaskContext;

CHAR g_AesEncCbcBuf[] = 
{
	0xFB, 0xE6, 0x22, 0xA9, 0xF6, 0xEB, 0x84, 0x2B, 0x76, 0xC3, 0x39, 0xFD, 0xE0, 0x64, 0x32, 0x2F,
	0xDA, 0xCF, 0xFA, 0xEA, 0xB5, 0x9D, 0x19, 0xD4, 0x90, 0xB5, 0xB1, 0xDF, 0x13, 0xBA, 0xF4, 0xC0,
	0xFC, 0x2D, 0x8F, 0xEF, 0xFF, 0xA4, 0x68, 0x2C, 0xC5, 0xA1, 0x40, 0x5B, 0x64, 0x03, 0xA5, 0x33,
	0xCC, 0x52, 0xFA, 0x16, 0x48, 0x24, 0x52, 0xCD, 0x32, 0xE6, 0xF0, 0x08, 0xCB, 0xF2, 0xE4, 0x3C,
	0x6E, 0xCE, 0x63, 0x20, 0x99, 0xF8, 0xE8, 0x61, 0x2D, 0x5C, 0x35, 0x5A, 0x32, 0x0B, 0x3D, 0xC5,
};

CHAR g_AesCbcRawBuf[] =
{
	0x43, 0x6f, 0x6d, 0x65, 0x20, 0x4f, 0x6e, 0x21, 0x20, 0x59, 0x6f, 0x75, 0x21, 0x20, 0x59, 0x6f, 
	0x75, 0x21, 0x20, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x20, 0x6e, 0x6f, 0x77, 0x2c, 0x6a, 0x69, 0x61, 
	0x6e, 0x20, 0x62, 0x69, 0x6e, 0x67, 0x20, 0x67, 0x75, 0x6f, 0x20, 0x7a, 0x69, 0x20, 0x6c, 0x61, 
	0x69, 0x20, 0x79, 0x69, 0x20, 0x74, 0x61, 0x6f, 0x21, 0x20, 0x79, 0x65, 0x61, 0x68, 0x21, 0x00,
};


CHAR g_AesOutpUT[256] = {0};

void g_CA_PrintfBuffer(CHAR* buf, UINT32 len)
{
	UINT32 index = 0U;
	for(index = 0U; index < len; index++){
		if(index < 15U){
	}else if(0U == index%16U){
		printf("\n");
	}
	else{
	}
	printf("0x%02x, ", (buf[index] & 0x000000FFU));
	}
	printf("\n");
}

static int l_CryptoVerifyCa_TaskInit(void)
{
	TEEC_Result result;
	int l_RetVal = OK;

	/**1) Check if need to do task initialization operation */
	if(-1 == g_TaskInitFlag){
		result = TEEC_InitializeContext(NULL, &g_TaskContext);
		if(result != TEEC_SUCCESS) {
		printf("InitializeContext failed, ReturnCode=0x%x\n", result);
		l_RetVal= FAIL;
		}else {
			g_TaskInitFlag = 1;
			printf("InitializeContext success\n");
			l_RetVal = OK;
		}
	}
	return l_RetVal;
}


static int l_CryptoVerifyCa_OpenSession(TEEC_Session* session)
{
	TEEC_Result result;
	int l_RetVal = FAIL;
	uint32_t origin;

	result = TEEC_OpenSession(&g_TaskContext, session, &svc_id, 
	TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if(result != TEEC_SUCCESS) {
		printf("OpenSession failed, ReturnCode=0x%x, ReturnOrigin=0x%x\n", result, origin);
		g_TaskInitFlag = -1;
		l_RetVal = FAIL;
	} else {
		printf("OpenSession success\n");
		l_RetVal = OK;
	}

	return l_RetVal;
}


static int l_CryptoVerifyCa_SendCommand(TEEC_Operation* operation, TEEC_Session* session, uint32_t commandID)
{
	TEEC_Result result;
	int l_RetVal = FAIL;
	uint32_t origin;

	result = TEEC_InvokeCommand(session, commandID, operation, &origin);
	if (result != TEEC_SUCCESS) {
		printf("InvokeCommand failed, ReturnCode=0x%x, ReturnOrigin=0x%x\n", result, origin);
		l_RetVal = FAIL;
	} else {
		printf("InvokeCommand success\n");
		l_RetVal = OK;
	}

	return l_RetVal;
}

int g_CryptoVerifyCa_Aes(CHAR* pData, UINT32 len, EN_AES_MODE aesMode, 
                         EN_AES_OPERATION_ACTION operAction, CHAR* output)
{
	TEEC_Session   l_session;
	TEEC_Operation l_operation;
	AesOperModeInfo l_aesMode;
	int l_RetVal = FAIL;

	l_RetVal = l_CryptoVerifyCa_TaskInit();
	if(FAIL == l_RetVal){
		goto cleanup_1;
	}

	l_RetVal = l_CryptoVerifyCa_OpenSession(&l_session);
	if(FAIL == l_RetVal){
		goto cleanup_2;
	}

	l_aesMode.active = operAction;
	l_aesMode.mode = aesMode;

	memset(&l_operation, 0x0, sizeof(TEEC_Operation));
	l_operation.started = 1;
	l_operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_INPUT, 
                                              TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_INOUT);
	l_operation.params[0].value.a = operAction;
	l_operation.params[0].value.b = aesMode;
	l_operation.params[1].tmpref.size = len;
	l_operation.params[1].tmpref.buffer = pData;
	l_operation.params[2].tmpref.size = len;
	l_operation.params[2].tmpref.buffer = output;
	l_operation.params[3].value.a = len;

	l_RetVal = l_CryptoVerifyCa_SendCommand(&l_operation, &l_session, CMD_AES_OPER);
	len=l_operation.params[3].value.a;
	printf("The respond data length is 0x%02x\n", len);
	printf("Output data just like follow:\n");
	g_CA_PrintfBuffer(g_AesOutpUT, len);
	if(FAIL == l_RetVal){
		goto cleanup_3;
	}

	cleanup_3:
		TEEC_CloseSession(&l_session);
	cleanup_2:
		TEEC_FinalizeContext(&g_TaskContext);
	cleanup_1:
		return l_RetVal;
}


int main(int argc, char *argv[])
{
	printf("dec-cbc  Input data length: 0x%x\n", sizeof(g_AesEncCbcBuf));
	printf("Input data just like follow:\n");
	g_CA_PrintfBuffer(g_AesEncCbcBuf, sizeof(g_AesEncCbcBuf));
	g_CryptoVerifyCa_Aes(g_AesEncCbcBuf, sizeof(g_AesEncCbcBuf), EN_MODE_CBC, EN_OP_AES_DECRYPT, g_AesOutpUT);
	return 0;
}
