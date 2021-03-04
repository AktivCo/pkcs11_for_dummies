/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2021, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*------------------------------------------------------------------------*
* Пример работы с Рутокен при помощи библиотеки PKCS#11 на языке C       *
*------------------------------------------------------------------------*
* Пример шифрования данных на секретном ключе ГОСТ 28147-89              *
*************************************************************************/

#include <Common.h>
#include "utils.h"

int encrypt_data_on_slot(CK_SESSION_HANDLE session, char* pin);
int encrypt_data(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE secretKey);
int gen_sec_key_gost(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR secretKey);

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
	
	if (encrypt_data_on_slot(slots[0], pin))
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

int encrypt_data_on_slot(CK_SLOT_ID slot, char* pin)
{
	CK_SESSION_HANDLE session;                         // Хэндл открытой сессии
	CK_OBJECT_HANDLE secretKey;
	int mech_support = 0;

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

	if (mech_supports(slot, CKM_GOST28147_KEY_GEN, &mech_support)
	    || !mech_support 
	    || gen_sec_key_gost(session, &secretKey)) {
		printf("Can't generate GOST secret key\n");
		goto logout;
	}
	if (mech_supports(slot, CKM_GOST28147, &mech_support)
            || !mech_support
	    || encrypt_data(session, secretKey))
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

int gen_sec_key_gost(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR secretKey)
{
	CK_OBJECT_CLASS secretKeyObject = CKO_SECRET_KEY;
	CK_BYTE secretKeyId[] = {"GOST 28147-89 Secret Key ID (Aktiv Co.)"};
	CK_KEY_TYPE keyTypeGost28147 = CKK_GOST28147;
	CK_BYTE parametersGost28147[] = { 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x1f, 0x01 };
        CK_BBOOL attributeTrue = CK_TRUE;

	CK_ATTRIBUTE secretKeyTemplate[] =
	{
		{ CKA_CLASS, &secretKeyObject, sizeof(secretKeyObject)},                   // Класс - секретный ключ
		{ CKA_ID, &secretKeyId, sizeof(secretKeyId) - 1},                          // Идентификатор ключа
		{ CKA_KEY_TYPE, &keyTypeGost28147, sizeof(keyTypeGost28147)},              // Тип ключа - ГОСТ 28147-89
		{ CKA_ENCRYPT, &attributeTrue, sizeof(attributeTrue)},                     // Ключ предназначен для зашифрования
		{ CKA_DECRYPT, &attributeTrue, sizeof(attributeTrue)},                     // Ключ предназначен для расшифрования
		{ CKA_TOKEN, &attributeTrue, sizeof(attributeTrue)},                       // Ключ является объектом токена
		{ CKA_PRIVATE, &attributeTrue, sizeof(attributeTrue)},                     // Ключ недоступен без аутентификации на токене
		{ CKA_GOST28147_PARAMS, parametersGost28147, sizeof(parametersGost28147)}  // Параметры алгоритма из стандарта
	};


	/*  Механизм генерации симметричного ключа по алгоритму ГОСТ 28147-89 */
	CK_MECHANISM gost28147KeyGenMech = {CKM_GOST28147_KEY_GEN, NULL_PTR, 0};

	CK_RV rv;
	int errorCode=1;

	/*************************************************************************
	* Сгенерировать секретный ключ ГОСТ 28147-89                             *
	*************************************************************************/
	printf("\nGenerating GOST 28147-89 secret key...\n");

	rv = functionList->C_GenerateKey(session, &gost28147KeyGenMech, secretKeyTemplate,
	                                 arraysize(secretKeyTemplate), secretKey);
	CHECK_AND_LOG(" C_GenerateKey", rv == CKR_OK, rvToStr(rv), exit);

	errorCode = 0;
	printf("Generating has been completed successfully.\n");

exit:
	return errorCode;
}

int encrypt_data(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE secretKey)
{
	/* Имитовставка */
	CK_BYTE iv[] = { 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x1f };
	/*  Механизм программного шифрования/расшифрования по алгоритму ГОСТ 28147-89 */
	CK_MECHANISM gost28147EncDecMech = {CKM_GOST28147, iv, sizeof(iv)};

	/*************************************************************************
	* Данные для шифрования                                                  *
	*************************************************************************/
	CK_BYTE data[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	               0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	               0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
	               0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00 };

	CK_BYTE_PTR encrypted;                            // Указатель на временный буфер для зашифрованных данных
	CK_ULONG encryptedSize;                           // Размер временного буфера в байтах
	
	CK_RV rv;
	int errorCode = 1;
	
	/*************************************************************************
	* Инициализировать операцию шифрования                                   *
	*************************************************************************/
	rv = functionList->C_EncryptInit(session, &gost28147EncDecMech, secretKey);
	CHECK_AND_LOG(" C_EncryptInit", rv == CKR_OK, rvToStr(rv), exit);

	/*************************************************************************
	* Зашифровать данные (при шифровании с использованием механизма          *
	* CKM_GOST28147_ECB размер данных должен быть кратен 8)                  *
	*************************************************************************/
	encryptedSize = sizeof(data);

	encrypted = (CK_BYTE_PTR)malloc(encryptedSize * sizeof(CK_BYTE));
	CHECK("  Memory allocation for encrypted data", encrypted != NULL_PTR, exit);

	rv = functionList->C_Encrypt(session, data, sizeof(data), encrypted, &encryptedSize);
	CHECK_AND_LOG(" C_Encrypt", rv == CKR_OK, rvToStr(rv), free_encrypted);

	/*************************************************************************
	* Распечатать буфер, содержащий зашифрованные данные                     *
	*************************************************************************/
	printf(" Encrypted buffer is:\n");
	printHex(encrypted, encryptedSize);

	printf("Encryption has been completed successfully.\n");

	errorCode = 0;
free_encrypted:
	free(encrypted);
exit:
	return errorCode;
}
