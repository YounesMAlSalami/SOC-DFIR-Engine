/*
 * Project: Log Story Studio (LSS) - Production Forensic Engine
 * File: c_ingestor/raw_pre_indexer.c
 * Standard: ISO C99 / C11 (Zero External Dependencies)
 * Compile (Linux/macOS): gcc -O3 -Wall -Wextra -Werror -pedantic c_ingestor/raw_pre_indexer.c -o c_ingestor/raw_pre_indexer
 * Compile (Windows MinGW): gcc -O3 -Wall -Wextra c_ingestor/raw_pre_indexer.c -o c_ingestor/raw_pre_indexer.exe
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_RECORD_BYTES 131072 /* 128 KB strict memory bound per record */

/*
 * Performs case-insensitive substring search without non-standard strcasestr.
 */
static int contains_token_ci(const char *haystack, const char *needle) {
    if (haystack == NULL || needle == NULL || *needle == '\0') {
        return 1;
    }
    size_t needle_len = strlen(needle);
    for (; *haystack != '\0'; ++haystack) {
        if (tolower((unsigned char)*haystack) == tolower((unsigned char)*needle)) {
            size_t i = 1;
            while (i < needle_len &&
                   haystack[i] != '\0' &&
                   tolower((unsigned char)haystack[i]) == tolower((unsigned char)needle[i])) {
                ++i;
            }
            if (i == needle_len) {
                return 1;
            }
        }
    }
    return 0;
}

/*
 * Strips trailing CR/LF and replaces control characters (except tab)
 * to guarantee single-line pipe-safe output for the Python bridge.
 */
static size_t sanitize_record(const char *src, char *dst, size_t dst_capacity) {
    size_t out_idx = 0;
    for (size_t i = 0; src[i] != '\0' && out_idx < (dst_capacity - 1); ++i) {
        unsigned char c = (unsigned char)src[i];
        if (c == '\r' || c == '\n') {
            continue;
        }
        if (c < 32 && c != '\t') {
            dst[out_idx++] = ' ';
        } else {
            dst[out_idx++] = (char)c;
        }
    }
    dst[out_idx] = '\0';
    return out_idx;
}

/*
 * Checks if a buffer contains only whitespace characters.
 */
static int is_blank_line(const char *buf) {
    for (size_t i = 0; buf[i] != '\0'; ++i) {
        if (!isspace((unsigned char)buf[i])) {
            return 0;
        }
    }
    return 1;
}

int main(int argc, char *argv[]) {
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "Usage: %s <raw_log_file_path> [optional_case_insensitive_filter]\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *file_path = argv[1];
    const char *filter_token = (argc == 3 && argv[2][0] != '\0') ? argv[2] : NULL;

    FILE *fp = fopen(file_path, "rb");
    if (fp == NULL) {
        perror("LSS_C_INDEXER_ERROR: Cannot open evidence file");
        return EXIT_FAILURE;
    }

    /* Set 64KB I/O stream buffer for high-throughput sequential disk reads */
    char io_buf[65536];
    setvbuf(fp, io_buf, _IOFBF, sizeof(io_buf));

    char *raw_line = (char *)malloc(MAX_RECORD_BYTES);
    char *clean_line = (char *)malloc(MAX_RECORD_BYTES);
    if (raw_line == NULL || clean_line == NULL) {
        fprintf(stderr, "LSS_C_INDEXER_ERROR: Memory allocation failed\n");
        free(raw_line);
        free(clean_line);
        fclose(fp);
        return EXIT_FAILURE;
    }

    unsigned long line_number = 0;
    long byte_offset = 0;

    while (1) {
        byte_offset = ftell(fp);
        if (byte_offset < 0) {
            byte_offset = 0;
        }

        if (fgets(raw_line, MAX_RECORD_BYTES, fp) == NULL) {
            break;
        }
        line_number++;

        /* Handle oversized lines that exceed MAX_RECORD_BYTES gracefully */
        size_t raw_len = strlen(raw_line);
        if (raw_len == (MAX_RECORD_BYTES - 1) && raw_line[raw_len - 1] != '\n') {
            int ch;
            while ((ch = fgetc(fp)) != '\n' && ch != EOF) {
                /* Drain remainder of oversized line to keep line numbers accurate */
            }
        }

        if (is_blank_line(raw_line)) {
            continue;
        }

        if (filter_token != NULL && !contains_token_ci(raw_line, filter_token)) {
            continue;
        }

        size_t clean_len = sanitize_record(raw_line, clean_line, MAX_RECORD_BYTES);
        if (clean_len == 0) {
            continue;
        }

        /*
         * Strict Output Protocol for Python Normalizer Bridge:
         * LINE_NUMBER|BYTE_OFFSET|CLEAN_BYTE_LENGTH|RAW_PAYLOAD
         */
        printf("%lu|%ld|%zu|%s\n", line_number, byte_offset, clean_len, clean_line);
    }

    free(raw_line);
    free(clean_line);
    fclose(fp);
    return EXIT_SUCCESS;
}
