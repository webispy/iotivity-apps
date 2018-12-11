CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(iotivity-apps)

INCLUDE(GNUInstallDirs)
INCLUDE(FindPkgConfig)

ADD_COMPILE_OPTIONS(
	-g
	-fPIC -fdata-sections -ffunction-sections -Wl,--gc-sections
	# Increased reliability of backtraces
	-fasynchronous-unwind-tables
	# Turn on all warnings and treat all warnings as errors.
	-Werror -Wall -Wextra
	# Additiional warnings
	-Wunreachable-code -Wpointer-arith -Waggregate-return
	-Wcast-align -Wformat=2
	# Not warnings
	-Wno-missing-field-initializers
	-Wno-missing-braces
	-Wno-unused-parameter)

# Common link options
LINK_LIBRARIES(-Wl,--as-needed)

INCLUDE_DIRECTORIES(
	${CMAKE_SOURCE_DIR}
	${CMAKE_SOURCE_DIR}/src
	${CMAKE_SOURCE_DIR}/external/stackmenu/src
	${CMAKE_BINARY_DIR})


pkg_check_modules(GLIB2 REQUIRED glib-2.0)
pkg_check_modules(IOTIVITY REQUIRED iotivity)

ADD_CUSTOM_COMMAND(OUTPUT ${CMAKE_BINARY_DIR}/default_db.c
	COMMAND IOTIVITY_LOG_LEVEL=4 ${IOTIVITY_LIBDIR}/iotivity/resource/csdk/security/tool/json2cbor ${CMAKE_SOURCE_DIR}/svr/server_svr_db.json ${CMAKE_BINARY_DIR}/server_svr_db.dat 1>/dev/null
	COMMAND IOTIVITY_LOG_LEVEL=4 ${IOTIVITY_LIBDIR}/iotivity/resource/csdk/security/tool/json2cbor ${CMAKE_SOURCE_DIR}/svr/client_svr_db.json ${CMAKE_BINARY_DIR}/client_svr_db.dat 1>/dev/null
	COMMAND IOTIVITY_LOG_LEVEL=4 ${IOTIVITY_LIBDIR}/iotivity/resource/csdk/security/tool/json2cbor ${CMAKE_SOURCE_DIR}/svr/obt_svr_db.json ${CMAKE_BINARY_DIR}/obt_svr_db.dat 1>/dev/null
	COMMAND ${CMAKE_SOURCE_DIR}/svr/generate_c.sh ${CMAKE_SOURCE_DIR}/svr ${CMAKE_BINARY_DIR} ${CMAKE_BINARY_DIR}/default_db.c
	COMMENT "Generating default SVR db control file")
ADD_CUSTOM_TARGET(default_db ALL DEPENDS ${CMAKE_BINARY_DIR}/default_db.c)

SET(COMMON_SRCS
	external/stackmenu/src/stackmenu.c
	src/security.c
	src/crudn.c
	src/common.c
	${CMAKE_BINARY_DIR}/default_db.c)

ADD_LIBRARY(objcommon OBJECT ${COMMON_SRCS})
TARGET_COMPILE_OPTIONS(objcommon PRIVATE ${GLIB2_CFLAGS} ${IOTIVITY_CFLAGS})
TARGET_COMPILE_DEFINITIONS(objcommon PRIVATE "-DBACKEND_GLIB")
ADD_DEPENDENCIES(objcommon default_db)

SET(APPLICATIONS
	server
	client
	obt)

FOREACH(app ${APPLICATIONS})
	# Link with IoTivity shared libraries
	ADD_EXECUTABLE(iotivity_${app}
		app/${app}.c
		$<TARGET_OBJECTS:objcommon>)
	TARGET_COMPILE_OPTIONS(iotivity_${app} PRIVATE ${GLIB2_CFLAGS} ${IOTIVITY_CFLAGS})
	TARGET_COMPILE_DEFINITIONS(iotivity_${app} PRIVATE "-DBACKEND_GLIB")
	TARGET_LINK_LIBRARIES(iotivity_${app}
		${IOTIVITY_LDFLAGS} ${GLIB2_LDFLAGS} "-lpthread")
	INSTALL(TARGETS iotivity_${app} DESTINATION ${CMAKE_INSTALL_BINDIR})

	# Link with IoTivity static libraries
	ADD_EXECUTABLE(iotivity_${app}_static
		app/${app}.c
		$<TARGET_OBJECTS:objcommon>)
	TARGET_COMPILE_OPTIONS(iotivity_${app}_static PRIVATE ${GLIB2_CFLAGS} ${IOTIVITY_CFLAGS})
	TARGET_COMPILE_DEFINITIONS(iotivity_${app}_static PRIVATE "-DBACKEND_GLIB")
	TARGET_LINK_LIBRARIES(iotivity_${app}_static
		${IOTIVITY_LIBDIR}/liboctbstack.a
		${IOTIVITY_LIBDIR}/libconnectivity_abstraction.a
		${IOTIVITY_LIBDIR}/liblogger.a
		${IOTIVITY_LIBDIR}/libocsrm.a
		${IOTIVITY_LIBDIR}/libmbedx509.a
		${IOTIVITY_LIBDIR}/libmbedtls.a
		${IOTIVITY_LIBDIR}/libmbedcrypto.a
		${IOTIVITY_LIBDIR}/libcoap.a
		${IOTIVITY_LIBDIR}/libroutingmanager.a
		${IOTIVITY_LIBDIR}/libc_common.a
		${IOTIVITY_LIBDIR}/libocpmapi.a
		${GLIB2_LDFLAGS} "-lpthread -lsqlite3")
	INSTALL(TARGETS iotivity_${app}_static DESTINATION ${CMAKE_INSTALL_BINDIR})
ENDFOREACH(app)

