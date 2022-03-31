include_directories(include)
include_directories(${CMAKE_SOURCE_DIR}/sql)

IF (CMAKE_SYSTEM_NAME MATCHES "Windows") # Windows OS use dll
	link_directories(lib)
    set(LIBHV_LIB "libhv.dll")
ELSE () # Other OS use find_library
    link_directories("/usr/local/lib")
    # find the absolute path of libhv and save to ${LIBHV_LIB}
    find_library(LIBHV_LIB
      NAMES libhv hv
      HINTS /usr/local/lib ${CMAKE_CURRENT_LIST_DIR}/lib
      REQUIRED)
ENDIF (CMAKE_SYSTEM_NAME MATCHES "Windows")

SET(SERVER_KEY_MANAGEMENT_PLUGIN_SOURCES server_key_management_plugin.cc)

MYSQL_ADD_PLUGIN(SERVER_KEY_MANAGEMENT ${SERVER_KEY_MANAGEMENT_PLUGIN_SOURCES})

target_link_libraries(server_key_management ${LIBHV_LIB})