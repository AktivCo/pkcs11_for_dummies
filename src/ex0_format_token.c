/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2021, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*------------------------------------------------------------------------*
* Пример работы с Рутокен при помощи библиотеки PKCS#11 на языке C       *
*------------------------------------------------------------------------*
* Пример форматирования устройств Рутокен                                *
*************************************************************************/

#include <Common.h>
#include "utils.h"

int format_token(CK_SLOT_ID slot, char* soPin);

int main(void)
{
	CK_SLOT_ID_PTR slots;                              // Массив идентификаторов слотов
	CK_ULONG slotCount;                                // Количество идентификаторов слотов в массиве
	char* soPin = "87654321";

	CK_RV rv;                                          // Код возврата. Могут быть возвращены только ошибки, определенные в PKCS#11
	int errorCode = 1;                                 // Флаг ошибки

	// инициализируем библиотеку
	if (init_pkcs11()) 
		goto exit;
		
	// получаем список слотов
	if (get_slot_list(&slots, &slotCount))
		goto free_pkcs11;

	if (slotCount == 0) {
		printf("No token found\n");
		goto free_slots;
	}

	// форматируем токен	
	if (format_token(slots[0], soPin))
		goto free_slots;


	errorCode = 0;

	/*************************************************************************
	* Очистить память, выделенную под слоты                                  *
	*************************************************************************/
free_slots:
	free(slots);

	/*************************************************************************
	* Деинициализировать библиотеку                                          *
	*************************************************************************/
free_pkcs11:
	free_pkcs11();

exit:
	if (errorCode) {
		printf("\n\nSome error occurred. Sample failed.\n");
	} else {
		printf("\n\nSample has been completed successfully.\n");
	}

	return errorCode;
}

int format_token(CK_SLOT_ID slot, char* soPin)
{
	CK_RUTOKEN_INIT_PARAM initParam;                   // Структура данных типа CK_RUTOKEN_INIT_PARAM, содержащая параметры для работы функции C_EX_InitToken

	CK_RV rv;                                          // Код возврата. Могут быть возвращены только ошибки, определенные в PKCS#11
	int errorCode = 1;

	initParam.ulSizeofThisStructure = sizeof(CK_RUTOKEN_INIT_PARAM);
	initParam.UseRepairMode = 0;
	initParam.pNewAdminPin = "87654321";
	initParam.ulNewAdminPinLen = 8;
	initParam.pNewUserPin = "12345678";
	initParam.ulNewUserPinLen = 8;
	initParam.ulMinAdminPinLen = 6;
	initParam.ulMinUserPinLen = 6;
	initParam.ChangeUserPINPolicy = (TOKEN_FLAGS_ADMIN_CHANGE_USER_PIN | TOKEN_FLAGS_USER_CHANGE_USER_PIN);
	initParam.ulMaxAdminRetryCount = 10;
	initParam.ulMaxUserRetryCount = 10;
	initParam.pTokenLabel = "rutoken";
	initParam.ulLabelLen = 7;
	initParam.ulSmMode = 0;
	
	/*************************************************************************
	* Инициализировать токен                                                 *
	*************************************************************************/
	rv = functionListEx->C_EX_InitToken(slot, soPin, strlen(soPin), &initParam);
	CHECK_AND_LOG(" C_EX_InitToken", rv == CKR_OK, rvToStr(rv), exit);

	errorCode = 0;
	printf("Token has been initialized successfully.\n");
exit:
	return errorCode;
}
