/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2021, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*------------------------------------------------------------------------*
* Пример работы с Рутокен при помощи библиотеки PKCS#11 на языке C       *
*------------------------------------------------------------------------*
* Пример формирования CMS на ключевой паре ГОСТ Р 34.10-2012             *
*************************************************************************/

#include <Common.h>
#include "utils.h"

int sign_cms_on_slot(CK_SLOT_ID slot, char* pin);
int sign_cms(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE certificate, CK_OBJECT_HANDLE privateKey);

int main(void)
{
	CK_SLOT_ID_PTR slots;                              // Массив идентификаторов слотов
	CK_ULONG slotCount;                                // Количество идентификаторов слотов в массиве
	char* pin = "12345678";
	
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
	
	// создание cms подписи	
	if (sign_cms_on_slot(slots[0], pin))
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

int sign_cms_on_slot(CK_SLOT_ID slot, char* pin)
{
	CK_SESSION_HANDLE session;                         // Хэндл открытой сессии
	CK_OBJECT_HANDLE privateKey, certificate;

	CK_RV rv;                                          // Код возврата. Могут быть возвращены только ошибки, определенные в PKCS#11
	int errorCode = 1;
	
	/*************************************************************************
	* Открыть RW сессию в первом доступном слоте                             *
	*************************************************************************/
	rv = functionList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &session);
	CHECK_AND_LOG(" C_OpenSession", rv == CKR_OK, rvToStr(rv), exit);

	/*************************************************************************
	* Выполнить аутентификацию Пользователя                                *
	*************************************************************************/
	rv = functionList->C_Login(session, CKU_USER, pin, strlen(pin));
	CHECK_AND_LOG(" C_Login (CKU_USER)", rv == CKR_OK, rvToStr(rv), close_session);

	
        if (find_certificate(session, &certificate)) {
                printf("No certificate found");
                goto logout;
        }
        if (find_private_key(session, &privateKey)) {
                printf("No private key found");
                goto logout;
        }

	if (sign_cms(session, certificate, privateKey))
		goto logout;

	errorCode = 0;

	/*************************************************************************
	* Сбросить права доступа                                                 *
	*************************************************************************/
logout:
	rv = functionList->C_Logout(session);
	CHECK_RELEASE_AND_LOG(" C_Logout", rv == CKR_OK, rvToStr(rv), errorCode);

	/*************************************************************************
	* Закрыть открытую сессию в слоте                                        *
	*************************************************************************/
close_session:
	rv = functionList->C_CloseSession(session);
	CHECK_RELEASE_AND_LOG(" C_CloseSession", rv == CKR_OK, rvToStr(rv), errorCode);
exit:
	return errorCode;
}

int sign_cms(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE certificate, CK_OBJECT_HANDLE privateKey)
{
	/*************************************************************************
	* Данные для подписи                                                     *
	*************************************************************************/
	CK_BYTE data[] =
	{
		0x01, 0x00, 0x02, 0x35, 0x35,
		0x02, 0x00, 0x01, 0x01,
		0x81, 0x00, 0x09, 0x34, 0x30, 0x34, 0x34, 0x34, 0x35, 0x39, 0x39, 0x38,
		0x82, 0x00, 0x0A, 0x37, 0x37, 0x38, 0x31, 0x35, 0x36, 0x34, 0x36, 0x31, 0x31,
		0x83, 0x00, 0x13, 0x41, 0x6B, 0x74, 0x69, 0x76, 0x20, 0x52, 0x75, 0x74, 0x6F, 0x6B, 0x65, 0x6E, 0x20, 0x42, 0x61, 0x6E, 0x6B, 0x2E,
		0x84, 0x00, 0x14, 0x34, 0x37, 0x37, 0x37, 0x38, 0x38, 0x38, 0x39, 0x39, 0x39, 0x31, 0x31, 0x31, 0x31, 0x31, 0x32, 0x32, 0x32, 0x37, 0x36,
		0x85, 0x00, 0x0A, 0x33, 0x32, 0x32, 0x38, 0x37, 0x33, 0x36, 0x37, 0x36, 0x35,
		0x86, 0x00, 0x03, 0x52, 0x55, 0x42,
		0xFF, 0x00, 0x0D, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30
	};

	CK_BYTE_PTR signature;                             // Указатель на буфер, содержащий подпись исходных данных
	CK_ULONG signatureSize;                            // Размер буфера, содержащего подпись исходных данных, в байтах
	char* signaturePem;                                // Строка с CMS в формате PEM
	
	CK_RV rv;
	int errorCode = 1;                                 // Флаг ошибки

	/*************************************************************************
	* Подписать данные                                                       *
	*************************************************************************/
	rv = functionListEx->C_EX_PKCS7Sign(session, data, sizeof(data), certificate,
		&signature, &signatureSize, privateKey, NULL_PTR, 0, USE_HARDWARE_HASH);
	CHECK_AND_LOG(" C_EX_PKCS7Sign", rv == CKR_OK, rvToStr(rv), exit);

        /*************************************************************************
        * Сконвертировать и распечатать буфер в формате PEM                      *
        *************************************************************************/
        GetCMSAsPEM(signature, signatureSize, &signaturePem);
        CHECK(" Get CMS in PEM format", signaturePem != NULL, free_signature);

        printf("\nSignature is:\n");
        printf("%s\n", signaturePem);


	errorCode = 0;
	printf("Data has been signed successfully.\n");

free_signature_pem:
	free(signaturePem);

	/*************************************************************************
	* Освободить память, выделенную в библиотеке                             *
	*************************************************************************/
free_signature:
	rv = functionListEx->C_EX_FreeBuffer(signature);
	CHECK_RELEASE_AND_LOG(" C_EX_FreeBuffer", rv == CKR_OK, rvToStr(rv), errorCode);

exit:
	return errorCode;
}
