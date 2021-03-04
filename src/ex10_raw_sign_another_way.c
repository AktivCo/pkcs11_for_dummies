/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2021, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*------------------------------------------------------------------------*
* Пример работы с Рутокен при помощи библиотеки PKCS#11 на языке C       *
*------------------------------------------------------------------------*
* Альтернативный пример формирования сырой подписи в два этапа:          *
* 1. взятие хеша от данных                                               *
* 2. подпись хеша                                                        *
*************************************************************************/

#include <Common.h>
#include "utils.h"

int sign_on_slot(CK_SLOT_ID slot, char* pin);
int sign(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE privateKey);


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

	// подпись данных на токене	
	if (sign_on_slot(slots[0], pin))
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

int sign_on_slot(CK_SLOT_ID slot, char* pin)
{
	CK_SESSION_HANDLE session;                         // Хэндл открытой сессии
	CK_OBJECT_HANDLE privateKey;
	
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

	 if (find_private_key(session, &privateKey)) {
                printf("No private key found\n");
		goto logout;
	 }

	if (sign(session, privateKey))
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

int sign(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE privateKey)
{
	/*  Механизм хеширования ГОСТ Р 34.11-2012(256) */
	CK_MECHANISM gostR3411_2012_256HashMech = { CKM_GOSTR3411_12_256, NULL_PTR, 0 };
	
	/*  Механизм подписи/проверки подписи по алгоритму ГОСТ Р 34.10-2012(256) */
	CK_MECHANISM gostR3410_2012_256SigVerMech = { CKM_GOSTR3410, NULL_PTR, 0 };
	
	CK_BYTE data[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
               0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
               0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
               0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
	
	CK_BYTE_PTR hash;                                 // Указатель на временный буфер для хэш-кода от данных
	CK_ULONG hashSize;                                // Размер временного буфера в байтах
	CK_BYTE_PTR signature;                            // Указатель на буфер, содержащий цифровую подпись для данных
	CK_ULONG signatureSize;                           // Размер буфера, содержащего цифровую подпись для данных, в байтах
	
	CK_RV rv;
	int errorCode = 1;

	/*************************************************************************
	* Вычислить хэш-код данных                                               *
	*************************************************************************/
	printf(" Hashing data...\n");

	/*************************************************************************
	* Инициализировать хэш-функцию                                           *
	*************************************************************************/
	rv = functionList->C_DigestInit(session, &gostR3411_2012_256HashMech);
	CHECK_AND_LOG("  C_DigestInit", rv == CKR_OK, rvToStr(rv), exit);

	/*************************************************************************
	* Определить размер хэш-кода                                             *
	*************************************************************************/
	rv = functionList->C_Digest(session, data, sizeof(data), NULL_PTR, &hashSize);
	CHECK_AND_LOG("  C_Digest(get size)", rv == CKR_OK, rvToStr(rv), exit);

	/*************************************************************************
	* Вычислить хэш-код данных                                               *
	*************************************************************************/

	hash = (CK_BYTE*)malloc(hashSize * sizeof(CK_BYTE));
	CHECK("  Memory allocation for hash", hash != NULL, exit);

	rv = functionList->C_Digest(session, data, sizeof(data), hash, &hashSize);
	CHECK_AND_LOG("  C_Digest (get hash)", rv == CKR_OK, rvToStr(rv), free_hash);

	/*************************************************************************
	* Распечатать буфер, содержащий хэш-код                                  *
	*************************************************************************/
	printf("  Hashed buffer is: \n");
	printHex(hash, hashSize);
	printf(" Hashing has been completed.\n");

	printf(" Signing data...\n");
	/*************************************************************************
	* Инициализировать операцию подписи данных                               *
	*************************************************************************/
	rv = functionList->C_SignInit(session, &gostR3410_2012_256SigVerMech, privateKey);
	CHECK_AND_LOG("  C_SignInit", rv == CKR_OK, rvToStr(rv), free_hash);

	/*************************************************************************
	* Определить размер данных подписи                                       *
	*************************************************************************/
	rv = functionList->C_Sign(session, hash, hashSize, NULL_PTR, &signatureSize);
	CHECK_AND_LOG("  C_Sign (get size)", rv == CKR_OK, rvToStr(rv), free_hash);

	/*************************************************************************
	 * Подписать данные                                                      *
	 ************************************************************************/
	signature = (CK_BYTE*)malloc(signatureSize * sizeof(CK_BYTE));
	CHECK("  Memory allocation for signature", signature != NULL, free_hash);

	rv = functionList->C_Sign(session, hash, hashSize, signature, &signatureSize);
	CHECK_AND_LOG("  C_Sign (signing)", rv == CKR_OK, rvToStr(rv), free_signature);

	/*************************************************************************
	* Распечатать буфер, содержащий подпись                                  *
	*************************************************************************/
	printf("  Signature buffer is: \n");
	printHex(signature, signatureSize);
	printf("Data has been signed successfully.\n");

	errorCode = 0;

free_signature:
	free(signature);
free_hash:
	free(hash);
exit:
	return errorCode;
}
