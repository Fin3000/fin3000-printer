/* Pure helpers from the actual backend, without a root invocation or queue. */
#define main fin3000_backend_main
#include "../../platforms/linux/cups-backend.c"
#undef main
#include <assert.h>

int main(void) {
    assert(uuid_valid("12345678-1234-1234-1234-123456789abc"));
    assert(!uuid_valid("12345678-1234-1234-1234-123456789abC"));
    assert(!uuid_valid("123456781234-1234-1234-123456789abc"));
    assert(!uuid_valid(NULL)); assert(!uuid_valid(""));
    assert(username_valid("synthetic_user-1"));
    assert(!username_valid("../root")); assert(!username_valid("root\n"));
    assert(!username_valid("-option")); assert(!username_valid("1invalid"));
    assert(spool_path("/var/spool/cups/d00012-001", 12));
    assert(spool_path("/var/spool/cups/d00012-002", 12));
    assert(spool_path("/var/spool/cups/d00012-999", 12));
    assert(spool_path("/var/spool/cups/d00012-1000", 12));
    assert(spool_path("/var/spool/cups/d100000-001", 100000));
    assert(spool_path("/var/spool/cups/d2147483647-2147483647", INT32_MAX));
    assert(!spool_path("/var/spool/cups/d00013-001", 12));
    assert(!spool_path("/var/spool/cups/d00012-001", 13));
    assert(!spool_path("/var/spool/cups/d00012-001", 0));
    assert(!spool_path("/var/spool/cups/d00012-001", -12));
    const char *invalid[] = {
        "/var/spool/cups/d00012-000", "/var/spool/cups/d00012-0000",
        "/var/spool/cups/d00012-0001", "/var/spool/cups/d00012-1",
        "/var/spool/cups/d00012-2147483648", "/var/spool/cups/d00012-+001",
        "/var/spool/cups/d00012--001", "/var/spool/cups/d00012-001\n",
        "/var/spool/cups/d00012-001/../secret", "/var/spool/cups/c00012",
        "/home/other/document.pdf", "/var/spool/cups/d-1", "/var/spool/cups/d1-",
        "/var/spool/cups/d12-001", "/var/spool/cups/d000012-001",
        "/var/spool/cups/d+0012-001", "/var/spool/cups/d 0012-001",
        "/var/spool/cups//d00012-001", "/var/spool/cups/d00012-001/",
        "/var/spool/cups/d00012-99999999999999999999999999999999999999999999999999",
        "", NULL,
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) assert(!spool_path(invalid[i], 12));
    for (int job = 1; job < 500; job++) {
        char path[64]; snprintf(path, sizeof(path), "/var/spool/cups/d%05d-%03d", job, job);
        assert(spool_path(path, job)); assert(!spool_path(path, job + 1));
    }
    assert(!enforcing()); /* Contract tests must never enter the root profile. */
    assert(setlocale(LC_CTYPE, "C.UTF-8"));
    char title[721]; safe_title("../Änderung\n\t.pdf\xe2\x80\xae", title);
    assert(!strcmp(title, "../Änderung.pdf"));
    char long_title[2048]; memset(long_title, 'x', sizeof(long_title) - 1); long_title[2047] = 0;
    safe_title(long_title, title); assert(strlen(title) == 180);
    struct json_object *root = json_object_new_object();
    json_object_object_add(root, "uid", json_object_new_int64(1000));
    json_object_object_add(root, "name", json_object_new_string_len("foo\0bar", 7));
    assert(json_integer(root, "uid", 1000)); assert(!json_integer(root, "uid", 1001));
    assert(!json_integer(root, "missing", 0)); assert(json_string(root, "name") == NULL);
    json_object_object_add(root, "uid", json_object_new_string("1000"));
    assert(!json_integer(root, "uid", 1000)); json_object_put(root);
    return 0;
}
