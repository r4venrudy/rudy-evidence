#include <rudy/evidence.h>
#include <stdio.h>
#include <string.h>
int main(void) {
    const char request[] = "{\"operation\":\"digest\",\"text\":\"abc\"}";
    re_buffer result = {0}, error = {0};
    int status = re_process(request, strlen(request), &result, &error);
    if (status == RE_OK) printf("%.*s\n", (int)result.size, result.data);
    re_free(&result); re_free(&error); return status;
}
