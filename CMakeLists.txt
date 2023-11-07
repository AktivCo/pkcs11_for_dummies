cmake_minimum_required (VERSION 3.0)
project (PKSC11_FOR_BABIES)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

include_directories(pkcs11_headers src/include)

add_library(utils src/utils.c)
target_compile_definitions(utils PRIVATE PKCS11_LIBRARY_DIR="${CMAKE_BINARY_DIR}")
if (WIN32)
	target_link_libraries(utils PUBLIC Kernel32 )
else()
	target_link_libraries(utils PUBLIC pthread dl)
endif(WIN32)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
	set(ARCH x64)
elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
	set(ARCH x32)
endif()

if (WIN32)
	set(librtpkcs11ecp_file_name rtpkcs11ecp.dll)
	set(librtpkcs11ecp_download_url https://download.rutoken.ru/Rutoken/PKCS11Lib/Current/Windows/${ARCH}/${librtpkcs11ecp_file_name})
endif (WIN32)

if (UNIX AND NOT APPLE)
	set(librtpkcs11ecp_file_name librtpkcs11ecp.so)
	set(librtpkcs11ecp_download_url http://download.rutoken.ru/Rutoken/PKCS11Lib/Current/Linux/${ARCH}/${librtpkcs11ecp_file_name})
endif (UNIX AND NOT APPLE)

if (APPLE)
	set(librtpkcs11ecp_file_name rtpkcs11ecp.dylib) 
	set(librtpkcs11ecp_download_url http://download.rutoken.ru/Rutoken/PKCS11Lib/Current/Mac/${ARCH}/${librtpkcs11ecp_file_name})
endif (APPLE)

set(librtpkcs11ecp_path ${CMAKE_BINARY_DIR}/${librtpkcs11ecp_file_name})
file(DOWNLOAD ${librtpkcs11ecp_download_url} ${librtpkcs11ecp_path})

add_custom_target(	librtpkcs11ecp 
			DEPENDS ${librtpkcs11ecp_path}
		)

set(examples    ex1_change_pin
                ex2_wait_for_slot_event
		ex3_gen_gost_key_pair
		ex4_raw_sign
		ex5_create_csr
		ex6_import_cert
		ex7_sign_cms
		ex8_get_cert_and_set_label
	        ex9_encrypt
		ex0_format_token
		ex10_raw_sign_another_way )

foreach(example IN LISTS examples)
        add_executable("${example}" "src/${example}.c")
        target_link_libraries ("${example}" PRIVATE utils)
	set_target_properties( "${example}" 
				PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/examples")
endforeach()

