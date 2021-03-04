/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2021, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*------------------------------------------------------------------------*
* Пример работы с Рутокен при помощи библиотеки PKCS#11 на языке C       *
*------------------------------------------------------------------------*
* Пример ожидания появления токена                                       *
*************************************************************************/

#include <Common.h>
#include "utils.h"

int monitor_slot_event();
void token_inserted(CK_SLOT_ID slot);
void print_token_info(void* slot_ptr);

int main(void)
{
	uintptr_t thread;
	
	CK_RV rv;                                          // Код возврата. Могут быть возвращены только ошибки, определенные в PKCS#11
	int errorCode = 1;                                 // Флаг ошибки

	// инициализируем библиотеку
	if (init_pkcs11()) 
		goto exit;
	
	// создаем отдельный поток для монитора событий токенов	
	createThread(&thread, NULL_PTR, &monitor_slot_event, NULL_PTR);

	printf("\n[Press any key to exit]\n");
	getchar();
	
	errorCode = 0;

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

int monitor_slot_event()
{
	int errorCode = 0;

	while (1) {
		CK_SLOT_ID slot ;
        	CK_RV rv = functionList->C_WaitForSlotEvent(0, &slot, NULL_PTR);
			
		if (CKR_CRYPTOKI_NOT_INITIALIZED == rv) break; // Индикатор того, что PKCS#11 деинициализирована из памяти.
		CHECK_RELEASE_AND_LOG(" C_WaitForSlotEvent", rv == CKR_OK, rvToStr(rv), errorCode);
		if (errorCode)
			break;

		CK_SLOT_INFO slotInfo;
		rv = functionList->C_GetSlotInfo(slot, &slotInfo); // получение информации о слоте
			
		if (CKR_CRYPTOKI_NOT_INITIALIZED == rv) break; // Индикатор того, что PKCS#11 деинициализирована из памяти.
		CHECK_RELEASE_AND_LOG(" C_GetSlotInfo", rv == CKR_OK, rvToStr(rv), errorCode);
		if (errorCode)
			break;
			
		if (CKF_TOKEN_PRESENT & slotInfo.flags) { 
                	token_inserted(slot);
		}
	}
}

void token_inserted(CK_SLOT_ID slot)
{
	uintptr_t thread;
	CK_SLOT_ID_PTR slot_p = malloc(sizeof(slot_p[0]));
	*slot_p = slot;
	createThread(&thread, NULL_PTR, &print_token_info, slot_p);
}

void print_token_info(void* slot_ptr)
{
	CK_SLOT_ID slot = *(CK_SLOT_ID*) slot_ptr;
	CK_TOKEN_INFO tokenInfo;
	CK_UTF8CHAR labelForPrinting[33] = { 0 };    // Буфер, используемый для печати метки Рутокен

	CK_RV rv;
	
	/*************************************************************************
	* Получить информацию о токене                                           *
	*************************************************************************/
	rv = functionList->C_GetTokenInfo(slot, &tokenInfo);
	CHECK_AND_LOG(" C_GetTokenInfo", rv == CKR_OK, rvToStr(rv), free_slot);

	/*************************************************************************
	* Распечатать информацию о токене                                        *
	*************************************************************************/
	printf("Printing token info:\n");
	printf(" Token label:               ");
	memcpy(labelForPrinting, tokenInfo.label, sizeof(tokenInfo.label));
	printUTF8String(labelForPrinting);
	printf("\n");
	printf(" Manufacturer:              %.*s \n", (int)sizeof(tokenInfo.manufacturerID), tokenInfo.manufacturerID);
	printf(" Token model:               %.*s \n", (int)sizeof(tokenInfo.model), tokenInfo.model);
	printf(" Token #:                   %.*s \n", (int)sizeof(tokenInfo.serialNumber), tokenInfo.serialNumber);
	printf(" Flags:                     0x%8.8X \n", (int)tokenInfo.flags);
	printf(" Max session count:         %d \n", (int)tokenInfo.ulMaxSessionCount);
	printf(" Current session count:     %d \n", (int)tokenInfo.ulSessionCount);
	printf(" Max RW session count:      %d \n", (int)tokenInfo.ulMaxRwSessionCount);
	printf(" Current RW session count:  %d \n", (int)tokenInfo.ulRwSessionCount);
	printf(" Max PIN length:            %d \n", (int)tokenInfo.ulMaxPinLen);
	printf(" Min PIN length:            %d \n", (int)tokenInfo.ulMinPinLen);
	printf(" Total public memory:       %d \n", (int)tokenInfo.ulTotalPublicMemory);
	printf(" Free public memory:        %d \n", (int)tokenInfo.ulFreePublicMemory);
	printf(" Total private memory:      %d \n", (int)tokenInfo.ulTotalPrivateMemory);
	printf(" Free private memory:       %d \n", (int)tokenInfo.ulFreePrivateMemory);
	printf(" Hardware version:          %d.%d \n", tokenInfo.hardwareVersion.major, tokenInfo.hardwareVersion.minor);
	printf(" Firmware version:          %d.%d \n", tokenInfo.firmwareVersion.major, tokenInfo.firmwareVersion.minor);
	printf(" Timer #:                   %.*s \n\n", (int)sizeof(tokenInfo.utcTime), tokenInfo.utcTime);

free_slot:
	free(slot_ptr);
}
