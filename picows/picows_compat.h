#pragma once

#if (defined(_WIN16) || defined(_WIN32) || defined(_WIN64)) && !defined(__WINDOWS__)
#	define __WINDOWS__
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
