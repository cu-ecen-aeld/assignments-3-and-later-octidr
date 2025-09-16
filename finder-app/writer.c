#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>

int main(int argc, char *argv[]) {
    openlog("writer", LOG_PID | LOG_CONS, LOG_USER);
    if (argc != 3) {
        syslog(LOG_ERR, "Usage: %s <write_file> <write_str>\n", argv[0]);
        closelog();
        return 1;
    }

    const char *writefile = argv[1];
    const char *writestr = argv[2];

    FILE *file = fopen(writefile, "w");
    if (!file) {
        syslog(LOG_ERR, "Error opening file %s: %s", writefile, strerror(errno));
        closelog();
        return 1;
    }

    syslog(LOG_DEBUG, "Writing %s to %s", writestr, writefile);

    if (fputs(writestr, file) == EOF) {
        syslog(LOG_ERR, "Error writing to file %s: %s", writefile, strerror(errno));
        fclose(file);
        closelog();
        return 1;
    }

    if (fclose(file) == EOF) {
        syslog(LOG_ERR, "Error closing file %s: %s", writefile, strerror(errno));
        closelog();
        return 1;
    }

    return 0;
}