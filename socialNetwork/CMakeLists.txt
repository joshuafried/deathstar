cmake_minimum_required(VERSION 3.5)
project(social_network_microservices)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "-O3")
set(CMAKE_INSTALL_PREFIX /users/friedj/install/)
set(CMAKE_PREFIX_PATH /users/friedj/install/)
set(CMAKE_LIBRARY_PATH /users/friedj/install/lib)
set(CMAKE_INCLUDE_PATH /users/friedj/install/include)

include_directories(/users/friedj/install/include)
link_directories(/users/friedj/install/lib)

add_subdirectory(src)
#add_subdirectory(test)
#enable_testing()


