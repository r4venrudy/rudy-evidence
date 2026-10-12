#include "rudy/evidence.h"
#include <stdio.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "C API failure at line %d\n", __LINE__); return 1; } } while (0)
int main(void) {
    const char request[] = "{\"operation\":\"digest\",\"text\":\"abc\"}";
    re_buffer result = {0}, error = {0};
    CHECK(re_abi_version() == 1 && strcmp(re_version(), "0.1.0") == 0);
    CHECK(re_process(NULL, 1, &result, &error) == RE_INVALID_ARGUMENT);
    CHECK(re_process(request, sizeof(request) - 1, &result, &result) == RE_INVALID_ARGUMENT);
    CHECK(re_process(request, sizeof(request) - 1, &result, &error) == RE_OK);
    CHECK(result.data && result.size == strlen(result.data) && !error.data);
    CHECK(strstr(result.data, "6437b3ac38465133") != NULL);
    CHECK(re_process(request, sizeof(request) - 1, &result, &error) == RE_INVALID_ARGUMENT);
    re_free(&result); re_free(&result); re_free(NULL);
    CHECK(!result.data && !result.size);
    CHECK(re_process("{bad", 4, &result, &error) == RE_INVALID_INPUT);
    CHECK(!result.data && error.data && error.size == strlen(error.data));
    re_free(&error);
    CHECK(re_process(request, sizeof(request), &result, &error) == RE_INVALID_INPUT);
    re_free(&error);
    CHECK(re_process(NULL, 0, &result, &error) == RE_INVALID_INPUT);
    re_free(&error);
    puts("C ABI ownership, invalid arguments, byte lengths and errors passed");
    return 0;
}
