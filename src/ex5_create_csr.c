/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2021, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*------------------------------------------------------------------------*
* Пример работы с Рутокен при помощи библиотеки PKCS#11 на языке C       *
*------------------------------------------------------------------------*
* Пример формирования заявки на сертификат                               *
*************************************************************************/

#include <Common.h>
#include "utils.h"

int create_csr_on_slot(CK_SLOT_ID slot, char* pin);
int create_csr(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE publicKey, CK_OBJECT_HANDLE privateKey);

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

	// создать заявку на сертификат для ключевой паре на токене	
	if (create_csr_on_slot(slots[0], pin))
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

int create_csr_on_slot(CK_SLOT_ID slot, char* pin)
{
	CK_SESSION_HANDLE session;                         // Хэндл открытой сессии
	CK_OBJECT_HANDLE publicKey, privateKey;

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

	if (find_public_key(session, &publicKey)) {
		printf("No public key found");
                goto logout;
	}
	if (find_private_key(session, &privateKey)) {
		printf("No private key found");
		goto logout;
	}
	if (create_csr(session, publicKey, privateKey))
		goto logout;

	printf("Sign created sucessfully\n");

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

int create_csr(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE publicKey, CK_OBJECT_HANDLE privateKey)
{
	/*************************************************************************
	* Запрос на получение сертификата                                        *
	*************************************************************************/
	/*************************************************************************
	* Список полей DN (Distinguished Name)                                   *
	*************************************************************************/
	CK_CHAR_PTR dn[] = { (CK_CHAR_PTR)"CN",                   // Тип поля CN (Common Name)
	                 (CK_CHAR_PTR)"UTF8String:Иванов",        // Значение
	                 (CK_CHAR_PTR)"C",                        // C (Country)
	                 (CK_CHAR_PTR)"RU",
	                 (CK_CHAR_PTR)"2.5.4.5",                  // SN (Serial Number)
	                 (CK_CHAR_PTR)"12312312312",
	                 (CK_CHAR_PTR)"1.2.840.113549.1.9.1",     // E (E-mail)
	                 (CK_CHAR_PTR)"ivanov@mail.ru",
	                 (CK_CHAR_PTR)"ST",                       // ST (State or province)
	                 (CK_CHAR_PTR)"UTF8String:Москва",
	                 (CK_CHAR_PTR)"O",                        // O (Organization)
	                 (CK_CHAR_PTR)"CompanyName",
	                 (CK_CHAR_PTR)"OU",                       // OU (Organizational Unit)
	                 (CK_CHAR_PTR)"Devel",
	                 (CK_CHAR_PTR)"L",                        // L (Locality)
	                 (CK_CHAR_PTR)"Moscow", };

	/*************************************************************************
	* Список дополнительных полей                                            *
	*************************************************************************/
	CK_CHAR_PTR exts[] = {(CK_CHAR_PTR)"keyUsage",                                                        // Использование ключа
	                  (CK_CHAR_PTR)"digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment",
	                  (CK_CHAR_PTR)"extendedKeyUsage",                                                    // Дополнительное использование
	                  (CK_CHAR_PTR)"1.2.643.2.2.34.6,1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4",
	                  (CK_CHAR_PTR)"2.5.29.17",                                                           // Дополнительное имя (пример с кодированием в виде DER)
	                  (CK_CHAR_PTR)"DER:30:0F:81:0D:65:78:61:6d:70:6c:65:40:79:61:2E:72:75",
	                  (CK_CHAR_PTR)"2.5.29.32",                                                           // Политики сертификата (кодирование в виде DER с пометкой "critical")
	                  (CK_CHAR_PTR)"critical,DER:30:0A:30:08:06:06:2A:85:03:64:71:01",
	                  (CK_CHAR_PTR)"1.2.643.100.111",                                                     // Средства электронной подписи владельца
	                  (CK_CHAR_PTR)"ASN1:UTF8String:СКЗИ \\\"Рутокен ЭЦП 2.0\\\"", };

	CK_BYTE_PTR csr;                                   // Указатель на буфер, содержащий подписанный запрос на сертификат
	CK_ULONG csrSize;                                  // Размер запроса на сертификат в байтах

	char* csrPem;                                      // Строка с CSR в формате PEM

	CK_RV rv;
	int errorCode = 1;
	
	/*************************************************************************
	* Создать запрос на сертификат                                           *
	*************************************************************************/
	printf("\nCreating CSR...\n");

	/*************************************************************************
	* Создание запроса на сертификат                                         *
	*************************************************************************/
	rv = functionListEx->C_EX_CreateCSR(session, publicKey, dn, arraysize(dn), &csr, &csrSize, privateKey, NULL_PTR, 0, exts, arraysize(exts));
	CHECK_AND_LOG(" C_EX_CreateCSR", rv == CKR_OK, rvToStr(rv), exit);

	/*************************************************************************
	* Сконвертировать и распечатать буфер в формате PEM                      *
	*************************************************************************/
	GetCSRAsPEM(csr, csrSize, &csrPem);
	CHECK(" Get CSR in PEM format", csrPem != NULL, free_csr);

	printf("\nCertificate request is:\n");
	printf("%s\n", csrPem);
	
	errorCode = 0;
	printf("Creating CSR has been completed successfully.\n");
free_csr_pem:
	free(csrPem);
free_csr:
	rv = functionListEx->C_EX_FreeBuffer(csr);
	CHECK_RELEASE_AND_LOG(" C_EX_FreeBuffer", rv == CKR_OK, rvToStr(rv), errorCode);
exit:
	return errorCode;
}
