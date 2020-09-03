cmake_minimum_required(VERSION 3.10.2)

project(mp-ecdsa-java-sdk)

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR})
set(CMAKE_CXX_STANDARD 11)
if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -framework Security")
endif()
set(CMAKE_BUILD_TYPE Release)
SET(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O3 -Wall -DNDEBUG")
find_package( Threads )
find_package(Java REQUIRED)
find_package(JNI REQUIRED)
include(UseJava)
include(ExternalProject)

include_directories(include)
include_directories(${JNI_INCLUDE_DIRS})
include_directories(${JAVA_INCLUDE_PATH})
include_directories(${JAVA_INCLUDE_PATH2})

link_directories(lib)

set(mpecdsa_jni_include org_tron_common_tss_Libmpecdsa_LibmpecdsaJNI.h)
set(mpecdsa_jni_src LibmpecdsaJNIImpl.cpp)
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/src mpecdsa_srcs)

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/include)
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/tmp)

include_directories("${CMAKE_CURRENT_SOURCE_DIR}")
include_directories("${CMAKE_BINARY_DIR}")
include_directories("${CMAKE_BINARY_DIR}/include")
include_directories("${CMAKE_CURRENT_SOURCE_DIR}/../rust/libmpecdsa/libmpecdsa/include")

add_custom_command(
		OUTPUT "${mpecdsa_jni_include}"
		COMMAND ${Java_JAVAC_EXECUTABLE} -verbose
		-h ${CMAKE_BINARY_DIR}/include
		-d ${CMAKE_BINARY_DIR}/tmp
		"${CMAKE_CURRENT_SOURCE_DIR}/../src/main/java/org/tron/common/tss/Libmpecdsa.java"
		DEPENDS ${mpecdsa_jni_include}
)

set_directory_properties(PROPERTIES EP_PREFIX ${CMAKE_BINARY_DIR}/rust)
set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES
		${CMAKE_CURRENT_SOURCE_DIR}/../rust/libmpecdsa/target
		)

ExternalProject_Add(
		libmpecdsa
		DOWNLOAD_COMMAND ""
		CONFIGURE_COMMAND ""
		BUILD_COMMAND cargo build
		#		COMMAND cargo build
		--package libmpecdsa
		--release
		BINARY_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../rust/libmpecdsa"
		INSTALL_COMMAND ""
		LOG_BUILD OFF)

add_custom_target(rust ALL DEPENDS libmpecdsa)

ADD_LIBRARY(mpecdsajni
		SHARED
		${CMAKE_CURRENT_SOURCE_DIR}/src/${mpecdsa_jni_src}
		${mpecdsa_src_dependencies}
		${mpecdsa_jni_include}
        ${mpecdsa_srcs}
		)

# GMP
find_package(GMP REQUIRED)
include_directories(${GMP_INCLUDE_DIR})

target_link_libraries(mpecdsajni
        ${GMP_LIBRARY}
		${CMAKE_THREAD_LIBS_INIT}
		${CMAKE_CURRENT_SOURCE_DIR}/../rust/libmpecdsa/target/release/libmpecdsa.a
	)

add_dependencies(mpecdsajni rust)

if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
	SET_TARGET_PROPERTIES( mpecdsajni PROPERTIES LINK_FLAGS "${LINK_FLAGS} -Wl,--wrap=memcpy" )
endif()

if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
	INSTALL(TARGETS mpecdsajni LIBRARY DESTINATION ${CMAKE_CURRENT_SOURCE_DIR}/../src/main/resources/native-package/linux)
else()
	INSTALL(TARGETS mpecdsajni LIBRARY DESTINATION ${CMAKE_CURRENT_SOURCE_DIR}/../src/main/resources/native-package/macos)
endif()
