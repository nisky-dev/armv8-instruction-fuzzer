cmake_minimum_required(VERSION 2.6.0)
SET( PROJECT_NAME 	"armtester")


project(${PROJECT_NAME} C)
include(FindPkgConfig)

pkg_check_modules (CAPSTONE REQUIRED capstone)


add_executable(armtester opcodeTester.c)
add_executable(cucheck cu_check.c disassembler.c)

# Use CAPSTONE_FOUND, CAPSTONE_LIBRARIES, CAPSTONE_INCLUDE_DIRS vars
target_link_libraries(${PROJECT_NAME} ${CAPSTONE_LIBRARIES})
