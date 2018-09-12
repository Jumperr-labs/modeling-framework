cmake_minimum_required(VERSION 3.0)
project(LSM6DSL)


#-std=c++11 -Werror -Wall -Wfatal-errors -Wno-shift-count-overflow -Weffc++ -Wno-non-virtual-dtor -Wno-strict-aliasing -Wno-unused-private-field

set(CMAKE_CXX_STANDARD 17)
#set(CMAKE_CXX_STANDARD "-Wall -g")
if (UNIX)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror -Wall -Wfatal-errors -Wno-shift-count-overflow -Weffc++ -Wno-non-virtual-dtor -Wno-strict-aliasing -Wno-unused-private-field")
    if (NOT APPLE)
        # set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread -lutil")
    endif()
endif()


if (WIN32)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    add_definitions(-D_CRT_NONSTDC_NO_DEPRECATE)
    add_definitions(-D_SCL_SECURE_NO_WARNINGS)
    add_definitions(-D_WINSOCK_DEPRECATED_NO_WARNINGS)
#add_definitions(-DVERBOSE)
endif()

set(BASE_DIR "../")

###################
## LSM6DSL
###################
file(GLOB SRC_FILES
        ${BASE_DIR}/src/*.cpp
        ${BASE_DIR}/../modeling-framework/src/*.cpp
        )

set(INCLUDE_FILES
        ${BASE_DIR}/include
        ${BASE_DIR}/../modeling-framework/include
        )

include_directories(${INCLUDE_FILES})

add_library(LSM6DSL SHARED ${SRC_FILES})
