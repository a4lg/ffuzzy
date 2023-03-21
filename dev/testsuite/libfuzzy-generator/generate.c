// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2023 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fuzzy.h>

#define FILE_BUFFER_ONCE_LIMIT (1024ul * 1024ul * 1024ul)
#define BUFSIZE 32768

size_t size_of_bh2(const char* hash)
{
    char* t = strchr(hash, ':');
    t++;
    t = strchr(t, ':');
    t++;
    return strlen(t);
}

unsigned get_was_long_flag(const char* hash)
{
    return size_of_bh2(hash) > (SPAMSUM_LENGTH / 2) ? 8 : 0;
}

int main(int argc, char** argv)
{
    char fuzzy_trunc_1_elimseq_0[FUZZY_MAX_RESULT];
    char fuzzy_trunc_0_elimseq_0[FUZZY_MAX_RESULT];
    char fuzzy_trunc_1_elimseq_1[FUZZY_MAX_RESULT];
    char fuzzy_trunc_0_elimseq_1[FUZZY_MAX_RESULT];
    char tmpstr1[FUZZY_MAX_RESULT];
    char tmpstr2[FUZZY_MAX_RESULT];
    unsigned char filebuf[BUFSIZE];
    FILE* fp;
    for (int i = 1; i < argc; i++)
    {
        char* filename = argv[i];
        // Find the file size
        fp = fopen(filename, "rb");
        if (!fp)
        {
            perror(filename);
            return 1;
        }
        if (fseeko(fp, 0, SEEK_END) != 0)
        {
            perror(filename);
            return 1;
        }
        off_t offset = ftello(fp);
        if (offset < 0)
        {
            perror(filename);
            return 1;
        }
        fclose(fp);
        uint_least64_t filesize = (uint_least64_t)offset;
        if (filesize != offset)
        {
            fprintf(stderr, "%s: arithmetic error on file size computation.\n", filename);
            return 1;
        }
        // Use fuzzy_hash_filename.
        if (fuzzy_hash_filename(filename, tmpstr1) < 0)
        {
            fprintf(stderr, "%s: failed to create fuzzy hash using fuzzy_hash_filename.\n", filename);
            return 1;
        }
        // Use fuzzy_hash_file.
        fp = fopen(filename, "rb");
        if (!fp)
        {
            perror(filename);
            return 1;
        }
        if (fuzzy_hash_file(fp, tmpstr2) < 0)
        {
            fprintf(stderr, "%s: failed to create fuzzy hash using fuzzy_hash_file.\n", filename);
            return 1;
        }
        if (strcmp(tmpstr1, tmpstr2))
        {
            fprintf(stderr, "%s: fuzzy_hash_file generated different result.\n", filename);
            fprintf(stderr, "String 1: %s\nString 2: %s\n", tmpstr1, tmpstr2);
            return 1;
        }
        fclose(fp);
        // Use fuzzy_hash_stream.
        fp = fopen(filename, "rb");
        if (!fp)
        {
            perror(filename);
            return 1;
        }
        if (fuzzy_hash_stream(fp, tmpstr2) < 0)
        {
            fprintf(stderr, "%s: failed to create fuzzy hash using fuzzy_hash_stream.\n", filename);
            return 1;
        }
        fclose(fp);
        if (strcmp(tmpstr1, tmpstr2))
        {
            fprintf(stderr, "%s: fuzzy_hash_stream generated different result.\n", filename);
            fprintf(stderr, "String 1: %s\nString 2: %s\n", tmpstr1, tmpstr2);
            return 1;
        }
        // Use fuzzy_hash_buf if the file is not too big.
        if (filesize <= FILE_BUFFER_ONCE_LIMIT)
        {
            fp = fopen(filename, "rb");
            if (!fp)
            {
                perror(filename);
                return 1;
            }
            size_t bufsize = (size_t)filesize;
            if (bufsize != filesize)
            {
                fprintf(stderr, "%s: arithmetic error on buffer size computation.\n", filename);
                return -1;
            }
            unsigned char* buffer = (unsigned char*)malloc(filesize);
            if (!buffer)
            {
                fprintf(stderr, "%s: error while making a buffer for file.\n", filename);
                return 1;
            }
            if (fread(buffer, 1, filesize, fp) != filesize)
            {
                perror(filename);
                free(buffer);
                return 1;
            }
            fclose(fp);
            if (fuzzy_hash_buf((const unsigned char*)buffer, (uint32_t)filesize, tmpstr2) < 0)
            {
                fprintf(stderr, "%s: failed to create fuzzy hash using fuzzy_hash_buf.\n", filename);
                free(buffer);
                return 1;
            }
            free(buffer);
            if (strcmp(tmpstr1, tmpstr2))
            {
                fprintf(stderr, "%s: fuzzy_hash_buf generated different result.\n", filename);
                fprintf(stderr, "String 1: %s\nString 2: %s\n", tmpstr1, tmpstr2);
                return 1;
            }
        }
        bool ignore_first = false;
#define TEST_OBJ_BASED_API(flags, tnum) \
        { \
            /* Use object-based API, without fixed size. */ \
            struct fuzzy_state *state = fuzzy_new(); \
            if (!state) \
            { \
                fprintf(stderr, "%s: failed to create fuzzy state object (TC%d-1).\n", filename, tnum); \
                return 1; \
            } \
            fp = fopen(filename, "rb"); \
            if (!fp) \
            { \
                perror(filename); \
                return 1; \
            } \
            while (true) \
            { \
                size_t bufsize = fread(filebuf, 1, sizeof(filebuf), fp); \
                if (bufsize == 0) \
                { \
                    if (ferror(fp)) \
                    { \
                        perror(filename); \
                        return 1; \
                    } \
                    break; \
                } \
                fuzzy_update(state, filebuf, bufsize); \
            } \
            fuzzy_digest(state, tmpstr2, flags); \
            fuzzy_free(state); \
            if (!ignore_first && strcmp(tmpstr1, tmpstr2)) \
            { \
                fprintf(stderr, "%s: object-API (without fixed length) generated different result.\n", filename); \
                fprintf(stderr, "String 1: %s\nString 2: %s\n", tmpstr1, tmpstr2); \
                return 1; \
            } \
        } \
        { \
            /* Use object-based API, with fixed size. */ \
            struct fuzzy_state *state = fuzzy_new(); \
            if (!state) \
            { \
                fprintf(stderr, "%s: failed to create fuzzy state object (TC%d-2).\n", filename, tnum); \
                return 1; \
            } \
            fp = fopen(filename, "rb"); \
            if (!fp) \
            { \
                perror(filename); \
                return 1; \
            } \
            if (fuzzy_set_total_input_length(state, filesize) < 0) \
            { \
                fprintf(stderr, "%s: failed to set fixed length (TC%d).\n", filename, tnum); \
                return 1; \
            } \
            while (true) \
            { \
                size_t bufsize = fread(filebuf, 1, sizeof(filebuf), fp); \
                if (bufsize == 0) \
                { \
                    if (ferror(fp)) \
                    { \
                        perror(filename); \
                        return 1; \
                    } \
                    break; \
                } \
                fuzzy_update(state, filebuf, bufsize); \
            } \
            if (fuzzy_digest(state, tmpstr1, flags) != 0) \
            { \
                fprintf(stderr, "%s: failed to obtain fuzzy hash (TC%d).\n", filename, tnum); \
                return 1; \
            } \
            fuzzy_free(state); \
            if (strcmp(tmpstr2, tmpstr1)) \
            { \
                fprintf(stderr, "%s: object-API (without fixed length) generated different result (TC%d).\n", filename, tnum); \
                fprintf(stderr, "String 1: %s\nString 2: %s\n", tmpstr2, tmpstr1); \
                return 1; \
            } \
        }
        // Fuzzy hashes generated above is a truncated one.
        TEST_OBJ_BASED_API(0, 1);
        strcpy(fuzzy_trunc_1_elimseq_0, tmpstr1);
        // Test other flags
        ignore_first = true;
        TEST_OBJ_BASED_API(FUZZY_FLAG_NOTRUNC, 2);
        strcpy(fuzzy_trunc_0_elimseq_0, tmpstr1);
        TEST_OBJ_BASED_API(FUZZY_FLAG_ELIMSEQ, 3);
        strcpy(fuzzy_trunc_1_elimseq_1, tmpstr1);
        TEST_OBJ_BASED_API(FUZZY_FLAG_NOTRUNC | FUZZY_FLAG_ELIMSEQ, 4);
        strcpy(fuzzy_trunc_0_elimseq_1, tmpstr1);
        // Print generated results
        if (strcmp(fuzzy_trunc_1_elimseq_0, fuzzy_trunc_0_elimseq_0) == 0)
        {
            printf("%s %2u %s\n", filename, 3u, fuzzy_trunc_1_elimseq_0);
            if (strcmp(fuzzy_trunc_1_elimseq_0, fuzzy_trunc_1_elimseq_1) != 0)
            {
                if (strcmp(fuzzy_trunc_1_elimseq_1, fuzzy_trunc_0_elimseq_1) != 0)
                {
                    fprintf(stderr, "%s: Different hash output depending on truncation.\n", filename);
                    return 1;
                }
                printf("%s %2u %s\n", filename, 7u, fuzzy_trunc_1_elimseq_1);
            }
        }
        else
        {
            printf("%s %2u %s\n", filename, 1u, fuzzy_trunc_1_elimseq_0);
            printf("%s %2u %s\n", filename, 2u, fuzzy_trunc_0_elimseq_0);
            if (strcmp(fuzzy_trunc_1_elimseq_0, fuzzy_trunc_1_elimseq_1) != 0)
                printf("%s %2u %s\n", filename, 5u | get_was_long_flag(fuzzy_trunc_1_elimseq_0), fuzzy_trunc_1_elimseq_1);
            if (strcmp(fuzzy_trunc_0_elimseq_0, fuzzy_trunc_0_elimseq_1) != 0)
                printf("%s %2u %s\n", filename, 6u | get_was_long_flag(fuzzy_trunc_0_elimseq_0), fuzzy_trunc_0_elimseq_1);
        }
    }
    return 0;
}
