/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2021, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*------------------------------------------------------------------------*
* Данный файл содержит объявление констант для работы с Рутокен при      *
* помощи библиотеки PKCS#11 на языке C                                   *
*************************************************************************/

#ifndef COMMON_H
#define COMMON_H

/************************************************************************
* Включение файлов:                                                     *
*  - stdio.h - для доступа к библиотеке стандартного ввода/вывода       *
*  - Windows.h - для доступа к функциям Win32API                        *
*  - WinCrypt.h - для доступа к функциям CryptoAPI                      *
*  - process.h - для доступа к функциям управления потоками и процессами*
*  - time.h - для доступа к функциям для работы со временем             *
*  - win2nix.h - для переопределения функций Windows для *nix-платформ  *
*  - wintypes.h - для переопределения типов данных Windows для          *
*    *nix-платформ                                                      *
*  - rtPKCS11.h - для доступа к функциям PKCS#11                        *
************************************************************************/
#ifdef _WIN32
	#include <stdio.h>
	#include <Windows.h>
	#include <WinCrypt.h>
	#include <process.h>
	#include <time.h>
#endif

#include "wintypes.h"
#include <rtpkcs11.h>
#include <win2nix.h>

/************************************************************************
* Макросы                                                               *
************************************************************************/
/* Имя библиотеки PKCS#11 */
#ifdef _WIN32
/* Библиотека для Рутокен S и Рутокен ЭЦП, поддерживает только алгоритмы RSA */
	#define PKCS11_LIBRARY_NAME         "rtPKCS11.dll"
/* Библиотека только для Рутокен ЭЦП, поддерживает алгоритмы ГОСТ и RSA */
	#define PKCS11ECP_LIBRARY_NAME      "rtPKCS11ECP.dll"
#endif
#ifdef __unix__
/* Библиотека только для Рутокен ЭЦП, поддерживает алгоритмы ГОСТ и RSA */
	#define PKCS11_LIBRARY_NAME         "librtpkcs11ecp.so"
	#define PKCS11ECP_LIBRARY_NAME      "librtpkcs11ecp.so"
#endif
#ifdef __APPLE__
/* Библиотека только для Рутокен ЭЦП, поддерживает алгоритмы ГОСТ и RSA */
	#define PKCS11_LIBRARY_NAME         "rtpkcs11ecp.framework/rtpkcs11ecp"
	#define PKCS11ECP_LIBRARY_NAME      "rtpkcs11ecp.framework/rtpkcs11ecp"
#endif

#ifndef TOKEN_TYPE_RUTOKEN
	#define TOKEN_TYPE_RUTOKEN 0x3
#endif

#ifdef _WIN32
	#define HAVEMSCRYPTOAPI
#endif

/* Вычисление размера массива */
#define arraysize(a)                (sizeof(a) / sizeof(a[0]))

/*************************************************************************
* Функция преобразования ошибки PKCS11 к строке                          *
*************************************************************************/
static const char* rvToStr(CK_RV rv)
{
	switch (rv) {
	case CKR_OK: return "CKR_OK";
	case CKR_CANCEL: return "CKR_CANCEL";
	case CKR_HOST_MEMORY: return "CKR_HOST_MEMORY";
	case CKR_SLOT_ID_INVALID: return "CKR_SLOT_ID_INVALID";
	case CKR_GENERAL_ERROR: return "CKR_GENERAL_ERROR";
	case CKR_FUNCTION_FAILED: return "CKR_FUNCTION_FAILED";
	case CKR_ARGUMENTS_BAD: return "CKR_ARGUMENTS_BAD";
	case CKR_NO_EVENT: return "CKR_NO_EVENT";
	case CKR_NEED_TO_CREATE_THREADS: return "CKR_NEED_TO_CREATE_THREADS";
	case CKR_CANT_LOCK: return "CKR_CANT_LOCK";
	case CKR_ATTRIBUTE_READ_ONLY: return "CKR_ATTRIBUTE_READ_ONLY";
	case CKR_ATTRIBUTE_SENSITIVE: return "CKR_ATTRIBUTE_SENSITIVE";
	case CKR_ATTRIBUTE_TYPE_INVALID: return "CKR_ATTRIBUTE_TYPE_INVALID";
	case CKR_ATTRIBUTE_VALUE_INVALID: return "CKR_ATTRIBUTE_VALUE_INVALID";
	case CKR_DATA_INVALID: return "CKR_DATA_INVALID";
	case CKR_DATA_LEN_RANGE: return "CKR_DATA_LEN_RANGE";
	case CKR_DEVICE_ERROR: return "CKR_DEVICE_ERROR";
	case CKR_DEVICE_MEMORY: return "CKR_DEVICE_MEMORY";
	case CKR_DEVICE_REMOVED: return "CKR_DEVICE_REMOVED";
	case CKR_ENCRYPTED_DATA_INVALID: return "CKR_ENCRYPTED_DATA_INVALID";
	case CKR_ENCRYPTED_DATA_LEN_RANGE: return "CKR_ENCRYPTED_DATA_LEN_RANGE";
	case CKR_FUNCTION_CANCELED: return "CKR_FUNCTION_CANCELED";
	case CKR_FUNCTION_NOT_PARALLEL: return "CKR_FUNCTION_NOT_PARALLEL";
	case CKR_FUNCTION_NOT_SUPPORTED: return "CKR_FUNCTION_NOT_SUPPORTED";
	case CKR_KEY_HANDLE_INVALID: return "CKR_KEY_HANDLE_INVALID";
	case CKR_KEY_SIZE_RANGE: return "CKR_KEY_SIZE_RANGE";
	case CKR_KEY_TYPE_INCONSISTENT: return "CKR_KEY_TYPE_INCONSISTENT";
	case CKR_KEY_NOT_NEEDED: return "CKR_KEY_NOT_NEEDED";
	case CKR_KEY_CHANGED: return "CKR_KEY_CHANGED";
	case CKR_KEY_NEEDED: return "CKR_KEY_NEEDED";
	case CKR_KEY_INDIGESTIBLE: return "CKR_KEY_INDIGESTIBLE";
	case CKR_KEY_FUNCTION_NOT_PERMITTED: return "CKR_KEY_FUNCTION_NOT_PERMITTED";
	case CKR_KEY_NOT_WRAPPABLE: return "CKR_KEY_NOT_WRAPPABLE";
	case CKR_KEY_UNEXTRACTABLE: return "CKR_KEY_UNEXTRACTABLE";
	case CKR_MECHANISM_INVALID: return "CKR_MECHANISM_INVALID";
	case CKR_MECHANISM_PARAM_INVALID: return "CKR_MECHANISM_PARAM_INVALID";
	case CKR_OBJECT_HANDLE_INVALID: return "CKR_OBJECT_HANDLE_INVALID";
	case CKR_OPERATION_ACTIVE: return "CKR_OPERATION_ACTIVE";
	case CKR_OPERATION_NOT_INITIALIZED: return "CKR_OPERATION_NOT_INITIALIZED";
	case CKR_PIN_INCORRECT: return "CKR_PIN_INCORRECT";
	case CKR_PIN_INVALID: return "CKR_PIN_INVALID";
	case CKR_PIN_LEN_RANGE: return "CKR_PIN_LEN_RANGE";
	case CKR_PIN_EXPIRED: return "CKR_PIN_EXPIRED";
	case CKR_PIN_LOCKED: return "CKR_PIN_LOCKED";
	case CKR_SESSION_CLOSED: return "CKR_SESSION_CLOSED";
	case CKR_SESSION_COUNT: return "CKR_SESSION_COUNT";
	case CKR_SESSION_HANDLE_INVALID: return "CKR_SESSION_HANDLE_INVALID";
	case CKR_SESSION_PARALLEL_NOT_SUPPORTED: return "CKR_SESSION_PARALLEL_NOT_SUPPORTED";
	case CKR_SESSION_READ_ONLY: return "CKR_SESSION_READ_ONLY";
	case CKR_SESSION_EXISTS: return "CKR_SESSION_EXISTS";
	case CKR_SESSION_READ_ONLY_EXISTS: return "CKR_SESSION_READ_ONLY_EXISTS";
	case CKR_SESSION_READ_WRITE_SO_EXISTS: return "CKR_SESSION_READ_WRITE_SO_EXISTS";
	case CKR_SIGNATURE_INVALID: return "CKR_SIGNATURE_INVALID";
	case CKR_SIGNATURE_LEN_RANGE: return "CKR_SIGNATURE_LEN_RANGE";
	case CKR_TEMPLATE_INCOMPLETE: return "CKR_TEMPLATE_INCOMPLETE";
	case CKR_TEMPLATE_INCONSISTENT: return "CKR_TEMPLATE_INCONSISTENT";
	case CKR_TOKEN_NOT_PRESENT: return "CKR_TOKEN_NOT_PRESENT";
	case CKR_TOKEN_NOT_RECOGNIZED: return "CKR_TOKEN_NOT_RECOGNIZED";
	case CKR_TOKEN_WRITE_PROTECTED: return "CKR_TOKEN_WRITE_PROTECTED";
	case CKR_UNWRAPPING_KEY_HANDLE_INVALID: return "CKR_UNWRAPPING_KEY_HANDLE_INVALID";
	case CKR_UNWRAPPING_KEY_SIZE_RANGE: return "CKR_UNWRAPPING_KEY_SIZE_RANGE";
	case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT: return "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT";
	case CKR_USER_ALREADY_LOGGED_IN: return "CKR_USER_ALREADY_LOGGED_IN";
	case CKR_USER_NOT_LOGGED_IN: return "CKR_USER_NOT_LOGGED_IN";
	case CKR_USER_PIN_NOT_INITIALIZED: return "CKR_USER_PIN_NOT_INITIALIZED";
	case CKR_USER_TYPE_INVALID: return "CKR_USER_TYPE_INVALID";
	case CKR_USER_ANOTHER_ALREADY_LOGGED_IN: return "CKR_USER_ANOTHER_ALREADY_LOGGED_IN";
	case CKR_USER_TOO_MANY_TYPES: return "CKR_USER_TOO_MANY_TYPES";
	case CKR_WRAPPED_KEY_INVALID: return "CKR_WRAPPED_KEY_INVALID";
	case CKR_WRAPPED_KEY_LEN_RANGE: return "CKR_WRAPPED_KEY_LEN_RANGE";
	case CKR_WRAPPING_KEY_HANDLE_INVALID: return "CKR_WRAPPING_KEY_HANDLE_INVALID";
	case CKR_WRAPPING_KEY_SIZE_RANGE: return "CKR_WRAPPING_KEY_SIZE_RANGE";
	case CKR_WRAPPING_KEY_TYPE_INCONSISTENT: return "CKR_WRAPPING_KEY_TYPE_INCONSISTENT";
	case CKR_RANDOM_SEED_NOT_SUPPORTED: return "CKR_RANDOM_SEED_NOT_SUPPORTED";
	case CKR_RANDOM_NO_RNG: return "CKR_RANDOM_NO_RNG";
	case CKR_DOMAIN_PARAMS_INVALID: return "CKR_DOMAIN_PARAMS_INVALID";
	case CKR_BUFFER_TOO_SMALL: return "CKR_BUFFER_TOO_SMALL";
	case CKR_SAVED_STATE_INVALID: return "CKR_SAVED_STATE_INVALID";
	case CKR_INFORMATION_SENSITIVE: return "CKR_INFORMATION_SENSITIVE";
	case CKR_STATE_UNSAVEABLE: return "CKR_STATE_UNSAVEABLE";
	case CKR_CRYPTOKI_NOT_INITIALIZED: return "CKR_CRYPTOKI_NOT_INITIALIZED";
	case CKR_CRYPTOKI_ALREADY_INITIALIZED: return "CKR_CRYPTOKI_ALREADY_INITIALIZED";
	case CKR_MUTEX_BAD: return "CKR_MUTEX_BAD";
	case CKR_MUTEX_NOT_LOCKED: return "CKR_MUTEX_NOT_LOCKED";
	case CKR_NEW_PIN_MODE: return "CKR_NEW_PIN_MODE";
	case CKR_NEXT_OTP: return "CKR_NEXT_OTP";
	case CKR_FUNCTION_REJECTED: return "CKR_FUNCTION_REJECTED";
	case CKR_CORRUPTED_MAPFILE: return "CKR_CORRUPTED_MAPFILE";
	case CKR_WRONG_VERSION_FIELD: return "CKR_WRONG_VERSION_FIELD";
	case CKR_WRONG_PKCS1_ENCODING: return "CKR_WRONG_PKCS1_ENCODING";
	case CKR_RTPKCS11_DATA_CORRUPTED: return "CKR_RTPKCS11_DATA_CORRUPTED";
	case CKR_RTPKCS11_RSF_DATA_CORRUPTED: return "CKR_RTPKCS11_RSF_DATA_CORRUPTED";
	case CKR_SM_PASSWORD_INVALID: return "CKR_SM_PASSWORD_INVALID";
	case CKR_LICENSE_READ_ONLY: return "CKR_LICENSE_READ_ONLY";
	default: return "Unknown error";
	}
}
/*************************************************************************
* Макросы проверки ошибки. Если произошла ошибка, то выводится           *
* сообщение и осуществляется переход на заданную метку                   *
*************************************************************************/
#define CHECK_AND_LOG(msg, expression, errMsg, label) \
	do { \
		printf("%s", msg); \
		if (!(expression)) { \
			printf(" -> Failed\n%s\n", errMsg); \
			goto label; \
		} \
		else { \
			printf(" -> OK\n"); \
		} \
	} while (0)

#define CHECK(msg, expression, label) \
	do { \
		printf("%s", msg); \
		if (!(expression)) { \
			printf(" -> Failed\n"); \
			goto label; \
		} \
		else { \
			printf(" -> OK\n"); \
		} \
	} while (0)

/*************************************************************************
* Макросы проверки ошибки при освобождении ресурсов . Если произошла     *
* ошибка, то выводится сообщение и выставляется                          *
* значение переменной errorCode                                          *
*************************************************************************/
#define CHECK_RELEASE_AND_LOG(msg, expression, errMsg, errorCode) \
	do { \
		printf("%s", msg); \
		if (!(expression)) { \
			printf(" -> Failed\n%s\n", errMsg); \
			errorCode = 1; \
		} \
		else { \
			printf(" -> OK\n"); \
		} \
	} while (0)

#define CHECK_RELEASE(msg, expression, errorCode) \
	do { \
		printf("%s", msg); \
		if (!(expression)) { \
			printf(" -> Failed\n"); \
			errorCode = 1; \
		} \
		else { \
			printf(" -> OK\n"); \
		} \
	} while (0)


/*************************************************************************
* Функция вывода шестнадцатеричного буфера заданной длины                *
*************************************************************************/
static void printHex(const CK_BYTE* buffer,   // Буфер
                     const CK_ULONG length)   // Длина буфера
{
	unsigned int i;
	const unsigned int width = 16;
	for (i = 0; i < length; ++i) {
		if (i % width == 0) {
			printf("   ");
		}

		printf("%02X ", buffer[i]);

		if ((i + 1) % width == 0 || (i + 1) == length) {
			printf("\n");
		}
	}
}

/*************************************************************************
* Функция выборки 6 бит из массива байт                                  *
*************************************************************************/
static CK_BYTE GetNext6Bit(CK_BYTE_PTR csr,          // Указатель на начало массива
                    CK_ULONG start,           // Номер бита в массиве, с которого начинается группа из 6 бит
                    CK_ULONG end              // Номер последнего бита массива
                    )
{
	CK_BYTE diff = start % 8;
	csr += start / 8;
	if (end - start > 8) {
		return 0x3F & (*csr << diff | *(csr + 1) >> (8 - diff)) >> 2;
	} else {
		return 0x3F & (*csr << diff >> 2);
	}
}

/*************************************************************************
* Функция конвертирования 6-битного кода в печатный символ Base64        *
*************************************************************************/
static char ConvertCodeToSymBase64(CK_BYTE code    // 6-битный код
                            )
{
	const char* alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	if (code < 0x40) {
		return alphabet[(int)code];
	} else {
		return '?';
	}
}

/*************************************************************************
* Функция конвертирования массива байт в строку Base64                   *
*************************************************************************/
static void ConvertToBase64String(CK_BYTE_PTR data,         // Исходные данные
                           CK_ULONG size,            // Длина исходного массива
                           char** result             // Результирующие данные (нуль-терминированная строка)
                           )
{
	CK_ULONG i = 0;
	char* pt;
	*result = (char*)calloc(((size_t)size + 2) / 3 * 4 + 1, sizeof(char));
	if (*result != NULL) {
		memset(*result, '=', ((size_t)size + 2) / 3 * 4);
		for (pt = *result; i < size * 8; i += 6, ++pt) {
			*pt = ConvertCodeToSymBase64(GetNext6Bit(data, i, size * 8));
		}
	}
}

/*************************************************************************
* Функция преобразования массива байт в PEM формат                       *
*************************************************************************/
static void GetBytesAsPem(CK_BYTE_PTR source,                  // Исходные данные
	               CK_ULONG size,                       // Длина исходного массива
	               const char* header,                  // Начальный тег
	               const char* footer,                  // Конечный тег
	               char** result                        // Результирующий запрос
                   )
{
	size_t length;
	size_t width = 0x40;
	char* buffer;
	size_t i;

	ConvertToBase64String(source, size, &buffer);
	if (buffer == NULL) {
		*result = NULL;
		return;
	}
	length = strlen(buffer);
	*result = (char*)calloc(strlen(header) // Место под начальный тег
		+ length                           // Место под base64 строку
		+ strlen(footer)                   // Место под конечный тег
		+ (length - 1) / width + 1         // Место под переносы строки
		+ 1,                               // Нуль-байт
		sizeof(char));
	if (*result == NULL) {
		free(buffer);
		return;
	}
	//компоновка данных
	strcat(*result, header);
	for (i = 0; i < length; i += width) {
		strncat(*result, buffer + i, width);
		strcat(*result, "\n");
	}
	strcat(*result, footer);

	free(buffer);
}

/*************************************************************************
* Функция получения CSR в формате PEM                                    *
*************************************************************************/
static void GetCSRAsPEM(CK_BYTE_PTR source,                  // Исходные данные
                  CK_ULONG size,                       // Длина исходного массива
                  char** result                        // Результирующий запрос
                  )
{
	const char* begin = "-----BEGIN NEW CERTIFICATE REQUEST-----\n"; // Начало запроса
	const char* end = "-----END NEW CERTIFICATE REQUEST-----\n";     // Конец запроса
	
	GetBytesAsPem(source, size, begin, end, result);
}

/*************************************************************************
* Функция получения CMS в формате PEM                                    *
*************************************************************************/
static void GetCMSAsPEM(CK_BYTE_PTR source,                  // Исходные данные
                  CK_ULONG size,                       // Длина исходного массива
                  char** result                        // Результирующий запрос
                  )
{
        const char* begin = "-----BEGIN CMS-----\n"; // Начало cms
        const char* end = "-----END CMS-----\n";     // Конец cms

        GetBytesAsPem(source, size, begin, end, result);
}

/*************************************************************************
* Функция получения тела сертификата в формате PEM                       *
*************************************************************************/
static void GetCertAsPem(CK_BYTE_PTR source,    // Исходные данные
	              CK_ULONG size,         // Длина исходного массива
	              char** result          // Указатель на строку с результатом
)
{
	const char* begin = "-----BEGIN CERTIFICATE-----\n"; // Начало сертификата
	const char* end = "-----END CERTIFICATE-----\n";     // Конец сертификата

	GetBytesAsPem(source, size, begin, end, result);
}

/*************************************************************************
* Функция вывода UTF-8. Выводит символы 0-127 и кириллицу. Возвращает 0  *
* в случае успешного выполнения, иначе не 0                              *
*************************************************************************/
static int printUTF8String(CK_BYTE* info)
{
#ifdef _WIN32
	CK_ULONG sym = 0;
	UINT cp = GetConsoleOutputCP();
	BOOL set = SetConsoleOutputCP(866); //кодировка cp-866
	if (set == FALSE)
		return 1;
	while (*info) {
		if (*info < 0x80) {
			printf("%c", *info);                         //вывод однобайтовых символов
			++info;
		}
		else if (*info & 0xC0) {                       //вывод двухбайтовых символов
			sym = ((*info & 0x1F) << 6) + (*(info + 1) & 0x3F);
			if (sym >= 0x0410 && sym <= 0x042F) {        //прописные
				printf("%c", sym - 0x0410 + 0x80);
			}
			else if (sym >= 0x0430 && sym <= 0x043F) { //строчные до 'р'
				printf("%c", sym - 0x0430 + 0xA0);
			}
			else if (sym >= 0x0440 && sym <= 0x044F) { //строчные после 'р'
				printf("%c", sym - 0x0440 + 0xE0);
			}
			else if (sym == 0x0401) {                  //Ё
				printf("%c", 0xF0);
			}
			else if (sym == 0x0451) {                  //ё
				printf("%c", 0xF1);
			}
			else {
				printf("?");                                 //все остальные двухбайтные символы
			}
			info += 2;
		}
		else if (*info & 0xE0) {        //трёх- и более байтные символы
			info += 3;
			printf("?");
		}
		else if (*info & 0xF0) {
			info += 4;
			printf("?");
		}
		else if (*info & 0xF8) {
			info += 5;
			printf("?");
		}
		else if (*info & 0xFC) {
			info += 6;
			printf("?");
		}
		else {
			++info;
		}
	}
	set = SetConsoleOutputCP(cp);
	return !set;
#else
	printf("%s", info);
	return 0;
#endif
}

#endif //COMMON_H

