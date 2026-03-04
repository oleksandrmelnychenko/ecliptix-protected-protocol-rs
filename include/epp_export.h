#pragma once

#if defined(_WIN32) || defined(__CYGWIN__)
  #if defined(ECLIPTIX_EXPORTS)
    #define EPP_API __declspec(dllexport)
  #elif defined(ECLIPTIX_SHARED)
    #define EPP_API __declspec(dllimport)
  #else
    #define EPP_API
  #endif
#elif defined(__GNUC__) && __GNUC__ >= 4
  #define EPP_API __attribute__((visibility("default")))
#else
  #define EPP_API
#endif
