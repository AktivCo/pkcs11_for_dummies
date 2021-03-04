/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2021, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*------------------------------------------------------------------------*
* Пример работы с Рутокен при помощи библиотеки PKCS#11 на языке C       *
*------------------------------------------------------------------------*
* Пример импорта сертификата ключевой пары на Рутокен                    *
*************************************************************************/

#include <Common.h>
#include "utils.h"

int import_cert_on_slot(CK_SLOT_ID slot, char* pin);
int import_cert(CK_SLOT_ID slot);

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

	// импорт сертификата ключевой пары на токен	
	if (import_cert_on_slot(slots[0], pin))
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

int import_cert_on_slot(CK_SLOT_ID slot, char* pin)
{
	CK_SESSION_HANDLE session;                         // Хэндл открытой сессии

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

	if (import_cert(session))
		goto logout;

	printf("Certeficate imported successfully\n");

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

int import_cert(CK_SESSION_HANDLE session)
{
	CK_OBJECT_CLASS certificateObject = CKO_CERTIFICATE;
	CK_BYTE keyPairIdGost2012_256[] = { "GOST R 34.10-2012 (256 bits) sample key pair ID (Aktiv Co.)" };
	CK_BBOOL attributeTrue = CK_TRUE;
	CK_BBOOL attributeFalse = CK_FALSE;
	CK_CERTIFICATE_TYPE certificateType = CKC_X_509;
	CK_ULONG tokenUserCertificate = 1;

	/*************************************************************************
	* Шаблон для импорта сертификата                                         *
	*************************************************************************/
	CK_ATTRIBUTE certificateTemplate[] =
	{
		{ CKA_VALUE, 0, 0 },                                                               // Значение сертификата (заполняется в процессе работы)
		{ CKA_CLASS, &certificateObject, sizeof(certificateObject) },                      // Класс - сертификат
		{ CKA_ID, &keyPairIdGost2012_256, sizeof(keyPairIdGost2012_256) - 1 },             // Идентификатор сертификата (совпадает с идентификатором соотвествующего ключа)
		{ CKA_TOKEN, &attributeTrue, sizeof(attributeTrue) },                              // Сертификат является объектом токена
		{ CKA_PRIVATE, &attributeFalse, sizeof(attributeFalse) },                          // Сертификат доступен без аутентификации
		{ CKA_CERTIFICATE_TYPE, &certificateType, sizeof(certificateType) },               // Тип сертификата - X.509
		{ CKA_CERTIFICATE_CATEGORY, &tokenUserCertificate, sizeof(tokenUserCertificate) }, // Категория сертификата - пользовательский
	};

	FILE* certFile;                                   // Поток ввода сертификата
	CK_BYTE_PTR certDer;                              // Массив с сертификатом в DER формате
	CK_ULONG certSize;                                // Размер массива сертификата

	CK_OBJECT_HANDLE certificate;                     // Хэндл сертификата

	CK_RV rv;
	int r;
	int errorCode = 1;                                // Флаг ошибки

	/*************************************************************************
	* Открыть поточный ввод сертификата из файла                             *
	*************************************************************************/
	certFile = fopen("cert_2012-256.cer", "rb");
	CHECK_AND_LOG(" fopen", certFile != NULL, "\"cert_2012-256.cer\" doesn't exist", exit);

	/*************************************************************************
	* Определить размер файла, содержащего сертификат                        *
	*************************************************************************/
	r = fseek(certFile, 0, SEEK_END);
	CHECK(" fseek", r == 0, close_certFile);
	certSize = ftell(certFile);
	CHECK(" ftell", certSize > 0, close_certFile);
	r = fseek(certFile, 0, SEEK_SET);
	CHECK(" fseek", r == 0, close_certFile);

	/*************************************************************************
	* Выделить память для сертификата                                        *
	*************************************************************************/
	certDer = (CK_BYTE_PTR)malloc(certSize);
	CHECK(" malloc", certDer != NULL, close_certFile);

	/*************************************************************************
	* Прочитать сертификат                                                   *
	*************************************************************************/
	r = (int)fread(certDer, 1, (int)certSize, certFile);
	CHECK(" fread", r == (int)certSize, free_certificate);

	/*************************************************************************
	* Задать шаблон сертификата для импорта                                  *
	*************************************************************************/
	certificateTemplate[0].pValue = certDer;
	certificateTemplate[0].ulValueLen = certSize;

	/*************************************************************************
	* Создать сертификат на токене                                         *
	*************************************************************************/
	rv = functionList->C_CreateObject(session, certificateTemplate, arraysize(certificateTemplate), &certificate);
	CHECK_AND_LOG(" C_CreateObject", rv == CKR_OK, rvToStr(rv), free_certificate);

	errorCode = 0;
	printf("Certificate has been created successfully\n");


	/*************************************************************************
	* Очистить память из-под строки с сертификатом                           *
	*************************************************************************/
free_certificate:
	free(certDer);

	/*************************************************************************
	* Закрыть поток ввода сертификата                                        *
	*************************************************************************/
close_certFile:
	r = fclose(certFile);
	CHECK_RELEASE(" fclose", r == 0, errorCode);

exit:
	return errorCode;
}
