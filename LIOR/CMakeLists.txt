cmake_minimum_required (VERSION 3.5.1)

### To use gcc/g++ on a Macintosh, you must set the Compilers
### here, not inside the project
##if(APPLE)
##       set(CMAKE_C_COMPILER "/usr/local/bin/gcc-7")
##       set(CMAKE_CXX_COMPILER "/usr/local/bin/g++-7")
##endif()
### TODO: for now, we use CLang for Mac
###
### In order to create OpenFHE's static libraries you should enable
### the BUILD_STATIC option. For that, you run "cmake .. -DBUILD_STATIC=ON".
### After having your link completed you will find static libs
### with the suffix "_static" in ./build/libs/.
### Examples: OPENFHEpke_static.a, OPENFHEcore_static.a, etc.
### After you run "make install" in your build directory, you can build your custom application.
### If you need your application to be linked statically, then run "cmake .. -DBUILD_STATIC=ON"
### /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin
###
###if(APPLE)
###       set(CMAKE_C_COMPILER "/Applications/Xcode.app/Contents/Developer/usr/bin/gcc")
###       set(CMAKE_CXX_COMPILER "/Applications/Xcode.app/Contents/Developer/usr/bin/g++")
###endif()

###-std=c++1z
set(CMAKE_C_COMPILER gcc)

project(demo CXX)
set(CMAKE_CXX_STANDARD 11)
option( BUILD_STATIC "Set to ON to include static versions of the library" OFF)

find_package(OpenFHE)
set(x "${OpenFHE_CXX_FLAGS} -std=c++1z")
set(y " ")
set(z "-Wall -DOPENFHE_VERSION=0.9.5  -Wno-unused-private-field -Wno-shift-op-parentheses -DMATHBACKEND=4 -Xpreprocessor -fopenmp -lomp -Wno-unused-command-line-argument -Xpreprocessor -fopenmp -lomp -Wno-unused-command-line-argument -Xpreprocessor -fopenmp -lomp -Wno-unused-command-line-argument -std=c++1z")

set(CMAKE_CXX_FLAGS ${z})

message(STATUS "LIORRRRinclude dir: ${CMAKE_CXX_FLAGS}")

include_directories( ${OPENMP_INCLUDES} )
include_directories( ${OpenFHE_INCLUDE} )
include_directories( ${OpenFHE_INCLUDE}/third-party/include )
include_directories( ${OpenFHE_INCLUDE}/core )
include_directories( ${OpenFHE_INCLUDE}/pke )
include_directories( ${OpenFHE_INCLUDE}/bigwig )

set(readBigWig "/Users/lior/libBigWig")
include_directories(${readBigWig})

message(STATUS "LIOR THIS IS BEING LINKED: ${OpenFHE_SHARED_LIBRARIES}")

### add directories for other OpenFHE modules as needed for your project

link_directories( ${OpenFHE_LIBDIR} )
link_directories( ${OPENMP_LIBRARIES} )
if(BUILD_STATIC)
    set( CMAKE_EXE_LINKER_FLAGS "${OpenFHE_EXE_LINKER_FLAGS} -static")
    link_libraries( ${OpenFHE_STATIC_LIBRARIES} )
else()
    set( CMAKE_EXE_LINKER_FLAGS ${OpenFHE_EXE_LINKER_FLAGS})
    link_libraries( ${OpenFHE_SHARED_LIBRARIES} /Users/lior/openfhe-development/build/src/bigwig/libBigWig.a)
endif()

### ADD YOUR EXECUTABLE(s) HERE
### add_executable( EXECUTABLE-NAME SOURCES )
###
### EXAMPLE:
### add_executable( test demo-simple-example.cpp )
add_executable( test lior.cpp )
