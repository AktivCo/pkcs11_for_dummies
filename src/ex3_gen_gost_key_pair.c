/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2021, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*------------------------------------------------------------------------*
* Пример работы с Рутокен при помощи библиотеки PKCS#11 на языке C       *
*------------------------------------------------------------------------*
* Пример генерации ключевой пары ГОСТ Р 34.10-2012                       *
*************************************************************************/

#include <Common.h>
#include "utils.h"

int gen_gost_key_pair_on_slot(CK_SLOT_ID slot, char* pin);
int gen_gost_key_pair(CK_SESSION_HANDLE session);

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
	
	// генерируем ключевую пару на слоте	
	if (gen_gost_key_pair_on_slot(slots[0], pin))
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

int gen_gost_key_pair_on_slot(CK_SLOT_ID slot, char* pin)
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

	if (gen_gost_key_pair(session))
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

int gen_gost_key_pair(CK_SESSION_HANDLE session)
{
	CK_KEY_TYPE keyTypeGostR3410_2012_256 = CKK_GOSTR3410;
	CK_BYTE keyPairIdGost2012_256[] = { "GOST R 34.10-2012 (256 bits) sample key pair ID (Aktiv Co.)" };
	CK_BYTE parametersGostR3410_2012_256[] = { 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x01 };
	CK_BYTE parametersGostR3411_2012_256[] = { 0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x02 };
	CK_BBOOL attributeTrue = CK_TRUE;
	CK_BBOOL attributeFalse = CK_FALSE;
	
	CK_OBJECT_CLASS publicKeyObject = CKO_PUBLIC_KEY;
	
	CK_ATTRIBUTE publicKeyTemplate[] =
	{
		{ CKA_CLASS, &publicKeyObject, sizeof(publicKeyObject)},                                        // Класс - открытый ключ
		{ CKA_ID, &keyPairIdGost2012_256, sizeof(keyPairIdGost2012_256) - 1 },                          // Идентификатор ключевой пары (должен совпадать у открытого и закрытого ключей)
		{ CKA_KEY_TYPE, &keyTypeGostR3410_2012_256, sizeof(keyTypeGostR3410_2012_256) },                // Тип ключа - ГОСТ Р 34.10-2012(256)
		{ CKA_TOKEN, &attributeTrue, sizeof(attributeTrue)},                                            // Ключ является объектом токена
		{ CKA_PRIVATE, &attributeFalse, sizeof(attributeFalse)},                                        // Ключ доступен без аутентификации на токене
		{ CKA_GOSTR3410_PARAMS, parametersGostR3410_2012_256, sizeof(parametersGostR3410_2012_256) },   // Параметры алгоритма ГОСТ Р 34.10-2012(256)
		{ CKA_GOSTR3411_PARAMS, parametersGostR3411_2012_256, sizeof(parametersGostR3411_2012_256) }    // Параметры алгоритма ГОСТ Р 34.11-2012(256)
	};
	
	CK_OBJECT_CLASS privateKeyObject = CKO_PRIVATE_KEY;
	
	CK_ATTRIBUTE privateKeyTemplate[] =
	{
		{ CKA_CLASS, &privateKeyObject, sizeof(privateKeyObject)},                                      // Класс - закрытый ключ
		{ CKA_ID, &keyPairIdGost2012_256, sizeof(keyPairIdGost2012_256) - 1 },                          // Идентификатор ключевой пары (должен совпадать у открытого и закрытого ключей)
		{ CKA_KEY_TYPE, &keyTypeGostR3410_2012_256, sizeof(keyTypeGostR3410_2012_256) },                // Тип ключа - ГОСТ Р 34.10-2012(256)
		{ CKA_TOKEN, &attributeTrue, sizeof(attributeTrue)},                                            // Ключ является объектом токена
		{ CKA_PRIVATE, &attributeTrue, sizeof(attributeTrue)},                                          // Ключ доступен только после аутентификации на токене
		{ CKA_GOSTR3410_PARAMS, parametersGostR3410_2012_256, sizeof(parametersGostR3410_2012_256) },   // Параметры алгоритма ГОСТ Р 34.10-2012(256)
		{ CKA_GOSTR3411_PARAMS, parametersGostR3411_2012_256, sizeof(parametersGostR3411_2012_256) }    // Параметры алгоритма ГОСТ Р 34.11-2012(256)
	};

	CK_OBJECT_HANDLE privateKey;                      // Хэндл закрытого ключа ГОСТ (ключевая пара для подписи и шифрования)	
	CK_OBJECT_HANDLE publicKey;                       // Хэндл открытого ключа ГОСТ (ключевая пара для подписи и шифрования)	
	
	CK_MECHANISM gostR3410_2012_256KeyPairGenMech = { CKM_GOSTR3410_KEY_PAIR_GEN, NULL_PTR, 0 };

	CK_RV rv;	
	int errorCode = 1;
	
	/*************************************************************************
	* Генериция ключевой пары на токене                                      *
	*************************************************************************/
	rv = functionList->C_GenerateKeyPair(session, &gostR3410_2012_256KeyPairGenMech, 
	publicKeyTemplate, arraysize(publicKeyTemplate),
	privateKeyTemplate, arraysize(privateKeyTemplate),
	&publicKey, &privateKey);
	CHECK_AND_LOG(" C_GenerateKeyPair", rv == CKR_OK, rvToStr(rv), exit);

	errorCode = 0;
	printf("Gost key pair generated sucessfully\n");
	
exit:
	return errorCode;
}
