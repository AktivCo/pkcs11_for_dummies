/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2021, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*------------------------------------------------------------------------*
* Пример работы с Рутокен при помощи библиотеки PKCS#11 на языке C       *
*------------------------------------------------------------------------*
* Заголовочный файл утилитарных функций для работы с PKCS#11             *
*************************************************************************/

#ifndef UTILS_H
#define UTILS_H

#include <Common.h>

extern CK_FUNCTION_LIST_PTR functionList;                 // Указатель на список функций PKCS#11, хранящийся в структуре CK_FUNCTION_LIST
extern CK_FUNCTION_LIST_EXTENDED_PTR functionListEx;      // Указатель на список функций расширения PKCS#11, хранящийся в структуре CK_FUNCTION_LIST_EXTENDED

/* Функция для инициализации библиотеки PKCS#11 */
int init_pkcs11();
/* Функция для деинициализации библиотеки PKCS#11 */
int free_pkcs11();
/* Функция для получения списка слотов */
int get_slot_list(CK_SLOT_ID_PTR* slots_ptr, CK_ULONG_PTR slotCount);

/* Функция для удобного поиска объектов на токене */
int findObjects(CK_SESSION_HANDLE session, CK_ATTRIBUTE_PTR attributes, CK_ULONG attrCount,
                CK_OBJECT_HANDLE objects[], CK_ULONG* objectsCount);

/* Функция для получения закрытого ГОСТ ключа на токене */
int find_private_key(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR privateKey);
/* Функция для получения открытого ГОСТ ключа на токене */
int find_public_key(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR publicKey);
/* Функция для получения сертификата ключа на токене */
int find_certificate(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR certificate);

/* Функция для удобной проверки поддержки конкретного механизма на токене */
int mech_supports(CK_SLOT_ID slot, CK_MECHANISM_TYPE mech, int* mechIsSupported);

#endif // UTILS_h
