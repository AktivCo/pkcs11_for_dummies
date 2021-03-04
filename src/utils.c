/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2021, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*------------------------------------------------------------------------*
* Пример работы с Рутокен при помощи библиотеки PKCS#11 на языке C       *
*------------------------------------------------------------------------*
* Утилитарные функции для работы с PKCS#11                               *
*************************************************************************/

#include "utils.h"

CK_FUNCTION_LIST_PTR functionList;                 // Указатель на список функций PKCS#11, хранящийся в структуре CK_FUNCTION_LIST
CK_FUNCTION_LIST_EXTENDED_PTR functionListEx;      // Указатель на список функций расширения PKCS#11, хранящийся в структуре CK_FUNCTION_LIST_EXTENDED
static HMODULE module;

int init_pkcs11()
{
	CK_C_GetFunctionList getFunctionList;              // Указатель на функцию C_GetFunctionList
	CK_C_EX_GetFunctionListExtended getFunctionListEx; // Указатель на функцию C_EX_GetFunctionListExtended

	/* Параметры для инициализации библиотеки: разрешаем использовать объекты синхронизации операционной системы */
	CK_C_INITIALIZE_ARGS initArgs = { NULL_PTR, NULL_PTR, NULL_PTR, NULL_PTR, CKF_OS_LOCKING_OK, NULL_PTR };

	CK_RV rv;					   // Код возврата PKCS#11 функций
	int errorCode = 1;                                 // Флаг ошибки

	/*************************************************************************
	* Выполнить действия для начала работы с библиотекой PKCS#11             *
	*************************************************************************/
	printf("Initialization...\n");

	/*************************************************************************
	* Загрузить библиотеку                                                   *
	*************************************************************************/
	module = LoadLibrary(PKCS11_LIBRARY_DIR "/" PKCS11ECP_LIBRARY_NAME);
	CHECK(" LoadLibrary", module != NULL, exit);

	/*************************************************************************
	* Получить адрес функции запроса структуры с указателями на функции      *
	*************************************************************************/
	getFunctionList = (CK_C_GetFunctionList)GetProcAddress(module, "C_GetFunctionList");
	CHECK(" GetProcAddress (C_GetFunctionList)", getFunctionList != NULL, unload_pkcs11);

	/*************************************************************************
	* Получить адрес функции запроса структуры с указателями на функции      *
	* расширения стандарта PKCS#11                                           *
	*************************************************************************/
	getFunctionListEx = (CK_C_EX_GetFunctionListExtended)GetProcAddress(module, "C_EX_GetFunctionListExtended");
	CHECK(" GetProcAddress (C_EX_GetFunctionListExtended)", getFunctionList != NULL, unload_pkcs11);

	/*************************************************************************
	* Получить структуру с указателями на функции                            *
	*************************************************************************/
	rv = getFunctionList(&functionList);
	CHECK_AND_LOG(" Get function list", rv == CKR_OK, rvToStr(rv), unload_pkcs11);

	/*************************************************************************
	* Получить структуру с указателями на функции расширения стандарта       *
	*************************************************************************/
	rv = getFunctionListEx(&functionListEx);
	CHECK_AND_LOG(" Get function list extended", rv == CKR_OK, rvToStr(rv), unload_pkcs11);

	/*************************************************************************
	* Инициализировать библиотеку                                            *
	*************************************************************************/
	rv = functionList->C_Initialize(&initArgs);
	CHECK_AND_LOG(" C_Initialize", rv == CKR_OK, rvToStr(rv), unload_pkcs11);

	errorCode = 0;
	
	/*************************************************************************
	* Выгрузить библиотеку из памяти                                         *
	*************************************************************************/
unload_pkcs11:
	if (errorCode)
		CHECK_RELEASE(" FreeLibrary", FreeLibrary(module), errorCode);
exit:
	return errorCode;
}

int free_pkcs11()
{
        CK_RV rv;
        int errorCode = 1;

        printf("\nFinalizing... \n");
	
	rv = functionList->C_Finalize(NULL_PTR);
        CHECK_RELEASE_AND_LOG(" C_Finalize", rv == CKR_OK, rvToStr(rv), errorCode);

	CHECK_RELEASE(" FreeLibrary", FreeLibrary(module), errorCode);

        return errorCode;
}


int get_slot_list(CK_SLOT_ID_PTR* slots_ptr, CK_ULONG_PTR slotCount)
{
	CK_RV rv;
	int errorCode = 1;
	
	/*************************************************************************
	* Получить количество слотов c подключенными токенами                    *
	*************************************************************************/
	rv = functionList->C_GetSlotList(CK_TRUE, NULL_PTR, slotCount);
	CHECK_AND_LOG(" C_GetSlotList (number of slots)", rv == CKR_OK, rvToStr(rv), exit);

	CHECK_AND_LOG(" Checking available tokens", *slotCount > 0, " No tokens available", exit);

	/*************************************************************************
	* Получить список слотов c подключенными токенами                        *
	*************************************************************************/
	*slots_ptr = (CK_SLOT_ID_PTR)malloc(*slotCount * sizeof(CK_SLOT_ID));
	CHECK(" Memory allocation for slots", *slots_ptr != NULL_PTR, exit);

	rv = functionList->C_GetSlotList(CK_TRUE, *slots_ptr, slotCount);
	CHECK_AND_LOG(" C_GetSlotList", rv == CKR_OK, rvToStr(rv), free_slots);
	printf(" Slots available: %d\n", (int)*slotCount);

	/*************************************************************************
	* Выставить признак успешного завершения программы                       *
	*************************************************************************/
	errorCode = 0;

free_slots:
	if (errorCode)
	{
		free(*slots_ptr);
	}

exit:
	return errorCode;
}

int findObjects(CK_SESSION_HANDLE session,         // Хэндл открытой сессии
                CK_ATTRIBUTE_PTR attributes,       // Массив с шаблоном для поиска
                CK_ULONG attrCount,                // Количество атрибутов в массиве поиска
                CK_OBJECT_HANDLE objects[],        // Массив для записи найденных объектов
                CK_ULONG* objectsCount             // Количество найденных объектов
                       )
{
	CK_RV rv;                                           // Код возврата. Могут быть возвращены только ошибки, определенные в PKCS#11
	int errorCode = 1;                                  // Флаг ошибки

	/*************************************************************************
	* Инициализировать операцию поиска                                       *
	*************************************************************************/
	rv = functionList->C_FindObjectsInit(session, attributes, attrCount);
	CHECK_AND_LOG("  C_FindObjectsInit", rv == CKR_OK, rvToStr(rv), exit);

	/*************************************************************************
	* Найти все объекты, соответствующие критериям поиска                    *
	*************************************************************************/

	rv = functionList->C_FindObjects(session, objects, *objectsCount, objectsCount);
	CHECK_AND_LOG("  C_FindObjects", rv == CKR_OK, rvToStr(rv), find_final);

	errorCode = 0;

	/*************************************************************************
	* Деинициализировать операцию поиска                                     *
	*************************************************************************/
find_final:
	rv = functionList->C_FindObjectsFinal(session);
	CHECK_RELEASE_AND_LOG("  C_FindObjectsFinal", rv == CKR_OK, rvToStr(rv), errorCode);

exit:
	return errorCode;
}

int find_private_key(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR privateKey)
{
        CK_BYTE keyPairIdGost2012_256[] = { "GOST R 34.10-2012 (256 bits) sample key pair ID (Aktiv Co.)" };
        CK_OBJECT_CLASS privateKeyObject = CKO_PRIVATE_KEY;

        CK_ATTRIBUTE privateKeyTemplate[] =
        {
                { CKA_CLASS, &privateKeyObject, sizeof(privateKeyObject)},              // Класс - закрытый ключ
                { CKA_ID, &keyPairIdGost2012_256, sizeof(keyPairIdGost2012_256) - 1},   // Идентификатор ключевой пары (должен совпадать у открытого и закрытого ключей)
        };

        CK_ULONG cnt = 1;

        CK_RV rv;
        int errorCode = 1;

        rv = findObjects(session, privateKeyTemplate,
        arraysize(privateKeyTemplate), privateKey, &cnt);

        CHECK(" findObjects", rv == 0, exit);
        CHECK_AND_LOG(" Checking number of keys found", cnt == 1, "No objects found\n", exit);

        errorCode = 0;
exit:
        return errorCode;
}

int find_public_key(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR publicKey)
{
        CK_BYTE keyPairIdGost2012_256[] = { "GOST R 34.10-2012 (256 bits) sample key pair ID (Aktiv Co.)" };
        CK_OBJECT_CLASS publicKeyObject = CKO_PUBLIC_KEY;

        CK_ATTRIBUTE publicKeyTemplate[] =
        {
                { CKA_CLASS, &publicKeyObject, sizeof(publicKeyObject)},                // Класс - открытый ключ
                { CKA_ID, &keyPairIdGost2012_256, sizeof(keyPairIdGost2012_256) - 1},   // Идентификатор ключевой пары (должен совпадать у открытого и закрытого ключей)
        };

        CK_ULONG cnt = 1;

        CK_RV rv;
        int errorCode = 1;

        rv = findObjects(session, publicKeyTemplate,
        arraysize(publicKeyTemplate), publicKey, &cnt);

        CHECK(" findObjects", rv == 0, exit);
        CHECK_AND_LOG(" Checking number of keys found", cnt == 1, "No objects found\n", exit);

        errorCode = 0;
exit:
        return errorCode;
}

int find_certificate(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR certificate)
{
        CK_BYTE keyPairIdGost2012_256[] = { "GOST R 34.10-2012 (256 bits) sample key pair ID (Aktiv Co.)" };
        CK_OBJECT_CLASS certificateObject = CKO_CERTIFICATE;

        CK_ATTRIBUTE certificateTemplate[] =
        {
                { CKA_CLASS, &certificateObject, sizeof(certificateObject)},            // Класс - закрытый ключ
                { CKA_ID, &keyPairIdGost2012_256, sizeof(keyPairIdGost2012_256) - 1},   // Идентификатор ключевой пары (должен совпадать у открытого и закрытого ключей)
        };

        CK_ULONG cnt = 1;

        CK_RV rv;
        int errorCode = 1;

        rv = findObjects(session, certificateTemplate,
        arraysize(certificateTemplate), certificate, &cnt);

        CHECK(" findObjects", rv == 0, exit);
        CHECK_AND_LOG(" Checking number of certificate found", cnt == 1, "No objects found\n", exit);

        errorCode = 0;
exit:
        return errorCode;
}


int mech_supports(CK_SLOT_ID slot, CK_MECHANISM_TYPE mech, int* mechIsSupported)
{
	CK_MECHANISM_TYPE_PTR mechanisms;                 // Массив поддерживаемых механизмов
	CK_ULONG mechanismCount;                          // Количество поддерживаемых механизмов
	
	CK_RV rv;
	int errorCode = 1;

	/*************************************************************************
	* Получить список поддерживаемых токеном механизмов                      *
	*************************************************************************/
	rv = functionList->C_GetMechanismList(slot, NULL_PTR, &mechanismCount);
	CHECK_AND_LOG(" C_GetMechanismList (number of mechanisms)", rv == CKR_OK, rvToStr(rv), exit);

	CHECK_AND_LOG(" Checking mechanisms available", mechanismCount > 0, " No mechanisms available", exit);

	mechanisms = (CK_MECHANISM_TYPE_PTR)malloc(mechanismCount * sizeof(CK_MECHANISM_TYPE));
	CHECK(" Memory allocation for mechanisms", mechanisms != NULL_PTR, exit);

	rv = functionList->C_GetMechanismList(slot, mechanisms, &mechanismCount);
	CHECK_AND_LOG(" C_GetMechanismList", rv == CKR_OK, rvToStr(rv), free_mechanisms);

	/*************************************************************************
	* Определение поддерживаемых токеном механизмов                          *
	*************************************************************************/
	for (size_t i = 0; i < mechanismCount; ++i) {
		if (mechanisms[i] == mech) {
			*mechIsSupported = 1;
			break;
		}
	}

	errorCode = 0;
	if (*mechIsSupported)
		printf("Mechanism is supported\n");
	else
		printf("Mechanism is not supported\n");

free_mechanisms:
	free(mechanisms);
exit:
	return errorCode;
}
