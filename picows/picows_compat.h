#pragma once

#include <errno.h>

#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif

#if (defined(_WIN16) || defined(_WIN32) || defined(_WIN64)) && !defined(__WINDOWS__)
    #define __WINDOWS__
    #define PLATFORM_IS_WINDOWS 1
#else
    #define PLATFORM_IS_WINDOWS 0
#endif

#ifdef __APPLE__
    #define PLATFORM_IS_APPLE 1
#else
    #define PLATFORM_IS_APPLE 0
#endif

#ifdef __linux__
    #define PLATFORM_IS_LINUX 1
#else
    #define PLATFORM_IS_LINUX 0
#endif

#if defined(__linux__)
    #include <arpa/inet.h>
    #include <endian.h>
#elif defined(__APPLE__)
    #include <arpa/inet.h>
    #include <libkern/OSByteOrder.h>
    #define be64toh(x) OSSwapBigToHostInt64(x)
    #define htobe64(x) OSSwapHostToBigInt64(x)
#elif defined(__OpenBSD__)
    #include <arpa/inet.h>
    #include <sys/endian.h>
#elif defined(__NetBSD__) || defined(__FreeBSD__) || defined(__DragonFly__)
    #include <arpa/inet.h>
    #include <sys/endian.h>
    #define be64toh(x) betoh64(x)
#elif defined(__WINDOWS__)
    #include <winsock2.h>
    #if BYTE_ORDER == LITTLE_ENDIAN
        #define be64toh(x) ntohll(x)
        #define htobe64(x) htonll(x)
    #elif BYTE_ORDER == BIG_ENDIAN
        #define be64toh(x) (x)
        #define htobe64(x) (x)
    #endif
#else
    error byte order not supported
#endif

#ifndef __WINDOWS__
    #include <sys/types.h>
    #include <sys/socket.h>
    #define PICOWS_SOCKET_ERROR -1
#else
    #include <winsock2.h>
    #define PICOWS_SOCKET_ERROR SOCKET_ERROR
#endif
