#ifndef RUDY_EVIDENCE_H
#define RUDY_EVIDENCE_H
#include <stddef.h>
#if defined(_WIN32) && defined(RE_BUILD_DLL)
#define RE_API __declspec(dllexport)
#elif defined(_WIN32)
#define RE_API __declspec(dllimport)
#else
#define RE_API __attribute__((visibility("default")))
#endif
#ifdef __cplusplus
extern "C" {
#endif
typedef struct re_buffer { char *data; size_t size; } re_buffer;
enum re_status { RE_OK = 0, RE_INVALID_ARGUMENT = 1, RE_INVALID_INPUT = 2, RE_INTERNAL_ERROR = 3 };
RE_API unsigned int re_abi_version(void);
RE_API const char *re_version(void);
// Both output buffers must be distinct, non-null and zero initialized.
// Input is length-delimited UTF-8; outputs are also NUL-terminated for convenience.
// On failure result stays empty and error contains a non-sensitive diagnostic.
RE_API int re_process(const char *request, size_t length, re_buffer *result, re_buffer *error);
// Free only buffers returned by this library. Safe for an empty buffer or NULL.
RE_API void re_free(re_buffer *buffer);
#ifdef __cplusplus
}
#endif
#endif
