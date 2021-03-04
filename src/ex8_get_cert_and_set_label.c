/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2021, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*------------------------------------------------------------------------*
* Пример работы с Рутокен при помощи библиотеки PKCS#11 на языке C       *
*------------------------------------------------------------------------*
* Пример чтения и установки атрибутов PKCS#11 объектов                   *
*************************************************************************/

#include <Common.h>
#include "utils.h"

int get_cert_and_set_label_on_slot(CK_SLOT_ID slot, char* pin);
int get_cert(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE cert);
int set_cert_label(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE cert);

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

	// получение тела сертификата хранящегося на токене и изменение его метки	
	if (get_cert_and_set_label_on_slot(slots[0], pin))
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

int get_cert_and_set_label_on_slot(CK_SLOT_ID slot, char* pin)
{
	CK_SESSION_HANDLE session;                         // Хэндл открытой сессии
	CK_OBJECT_HANDLE certificate;

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

	if (get_cert(session, certificate))
		goto logout;

	if (set_cert_label(session, certificate))
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

int get_cert(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE cert)
{
	CK_BYTE_PTR body = NULL_PTR;
	CK_ATTRIBUTE template[] = {
		{CKA_VALUE, NULL_PTR, 0}
	};

	char* certPem;
	
	CK_RV rv;
	int errorCode=1;

        /*************************************************************************
        * Получение размера тела сертификата                                     *
        *************************************************************************/
	rv = functionList->C_GetAttributeValue(session, cert, template, arraysize(template));
	CHECK_AND_LOG(" C_GetAttributeValue", rv == CKR_OK, rvToStr(rv), exit);

	body = (CK_BYTE_PTR) malloc(template[0].ulValueLen);
	template[0].pValue = body;

        /*************************************************************************
        * Получение тела сертификата в формате DER                               *
        *************************************************************************/
	rv = functionList->C_GetAttributeValue(session, cert, template, arraysize(template));
	CHECK_AND_LOG(" C_GetAttributeValue", rv == CKR_OK, rvToStr(rv), free);

        /*************************************************************************
        * Сконвертировать и распечатать буфер в формате PEM                      *
        *************************************************************************/
        GetCertAsPem(body, template[0].ulValueLen, &certPem);
        CHECK(" Get cert in PEM format", certPem != NULL, free);

        printf("\nCertificate request is:\n");
        printf("%s\n", certPem);

	errorCode = 0;
        printf("Getting cert body has been completed successfully.\n");

free_cert_pem:
        free(certPem);
free:
	free(body);
exit:
	return errorCode;
}

int set_cert_label(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE cert)
{
	CK_UTF8CHAR label[] = {"GOST certificate"};

	CK_ATTRIBUTE template[] = {
		CKA_LABEL, label, sizeof(label)-1
	};

	CK_RV rv;
	int errorCode = 1;
	
        /*************************************************************************
        * Установка метки сертификата                                            *
        *************************************************************************/
	rv = functionList->C_SetAttributeValue(session, cert, template, arraysize(template));
	CHECK_AND_LOG(" C_SetAttributeValue", rv == CKR_OK, rvToStr(rv), exit);

	errorCode = 0;

exit:
	return errorCode;
}
