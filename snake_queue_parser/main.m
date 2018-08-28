/*
 *  _____         _          _____                    _____
 * |   __|___ ___| |_ ___   |     |_ _ ___ _ _ ___   |  _  |___ ___ ___ ___ ___
 * |__   |   | .'| '_| -_|  |  |  | | | -_| | | -_|  |   __| .'|  _|_ -| -_|  _|
 * |_____|_|_|__,|_,_|___|  |__  _|___|___|___|___|  |__|  |__,|_| |___|___|_|
 *                             |__|
 *
 *  snake_queue_parser
 *  A parser and decryptor for Snake/Turla configuration files
 *
 *  Created by reverser on 26/06/2018.
 *  Copyright © 2018 Put.as. All rights reserved.
 *
 *  main.m
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#import <Foundation/Foundation.h>

#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <openssl/cast.h>

#include "logging.h"

/*
 Decrypted payload [0x64]: 2
 Decrypted payload [0x65]: enc.unix//tmp/.gdm-socket
 Decrypted payload [0x66]: enc.frag.reliable.doms.unix//tmp/.gdm-selinux
 Decrypted payload [0x70]: read_peer_nfo=Y,psk=!HqACg3ILQd-w7e4
 Decrypted payload [0x71]: psk=R@gw1gBsRP!5!yj0
 Decrypted payload [0xc8]: 1
 Decrypted payload [0xc9]: enc.http.tcp/car-service.effers.com:80
 Decrypted payload [0xd4]: psk=1BKQ55n6#OsIgwn*,ustart=bc41f8cd.0
 Decrypted payload [0x12c]: 1
 Decrypted payload [0x12d]: enc.http.tcp/car-service.effers.com:80
 Decrypted payload [0x138]: psk=1BKQ55n6#OsIgwn*,ustart=bc41f8cd.0
 */
enum snake_cmds
{
    kCmdTotalPipeObjects = 0x64,
    /* 0x65 to 0x6F - pipe names */
    kCmdUnixPipe = 0x65,            /* enc.unix */
    kCmdFragUnixPipe = 0x66,        /* enc.frag.reliable.doms.unix */
    /* 0x70 to 0x79 - pipe options */
    kCmdUnixPipeOptions = 0x70,
    kCmdFragUnixPipeOptions = 0x71,
    kCmdEncryptionKey = 0x229
};

/* the file header at the beginning */
struct __attribute__((packed)) queue_header
{
    int queue_file_size;    /* offset 0x0 */
    int queue_file_size2;   /* offset 0x4 */
    int unknown_var1;       /* offset 0x8 */
    int unknown_var2;       /* offset 0xC */
    int unknown_var3;       /* offset 0x10 */
    int data_size;          /* offset 0x14 - the amount of data that queue file contains */
    int64_t unknown_var4;   /* offset 0x18 */
    int unknown_var5;       /* offset 0x20 */
    int unknown_var6;       /* offset 0x24 */
    int mutex_name;         /* offset 0x28 - used to create a mutex - same as Windows version */
};

/* and then the rest of the file is composed of records that contain an header plus data if available */
struct __attribute__((packed)) queue_record_header
{
    int record_id;          /* offset 0x0 */
    int index;              /* offset 0x4 - this is an index but depends on next field */
    int record_type;        /* offset 0x8 - it appears to be some kind of type 0x2 for commands, 0xb for something else (first record for example), 0x4 for logs? */
    int cmd_id;             /* offset 0xC */
    int next_record_id;     /* offset 0x10 */
    int unknown_var4;       /* offset 0x14 - unused? */
    int unknown_var5;       /* offset 0x18 - unused? */
    int unknown_var6;       /* offset 0x1C - unused? */
    int timestamp;          /* offset 0x20 - no idea what this is, after some records it changes */
    int unknown_var7;       /* offset 0x24 - in some records it is equal to the value that changes above */
    int timestamp2;         /* offset 0x28 - always equal to timestamp */
    int record_data_size;   /* offset 0x2C - the size of the data trailer */
    int record_data_size2;  /* offset 0x30 - appears to be duplicate of previous */
    int unknown_var10;      /* offset 0x34 - ?? */
    int unknown_var11;      /* offset 0x38 - unused? */
    int unknown_var12;      /* offset 0x3C - unused? */
};

void
help(const char *name)
{
    printf(
           " _____         _       _____\n"
           "|   __|___ ___| |_ ___|  _  |___ ___ ___ ___ ___\n"
           "|__   |   | .'| '_| -_|   __| .'|  _|_ -| -_|  _|\n"
           "|_____|_|_|__,|_,_|___|__|  |__,|_| |___|___|_|\n"
           "---[ Usage: ]---\n"
           "%s -i queue file [-v] [-h]\n\n"
           "-i: path to Snake/Turla queue file to parse\n"
           "-v: verbose debug output\n"
           "-h: help\n"
           "", name);
}

int main(int argc, const char * argv[])
{
    @autoreleasepool
    {
        static struct option long_options[] = {
            { "verbose", no_argument, NULL, 'v' },
            { "input", required_argument, NULL, 'i' },
            { "help", no_argument, NULL, 'h' },
            { NULL, 0, NULL, 0 }
        };
        
        int option_index = 0;
        int c = 0;
        const char *input_file = NULL;
        int verbose = 0;
        
        // process command line options
        while ((c = getopt_long (argc, (char * const*)argv, "vhi:", long_options, &option_index)) != -1)
        {
            switch (c)
            {
                case 'i':
                {
                    input_file = optarg;
                    break;
                }
                case 'v':
                {
                    verbose = 1;
                    break;
                }
                case 'h':
                {
                    help(argv[0]);
                    exit(0);
                }
                default:
                    break;
            }
        }
        
        if (input_file == NULL)
        {
            ERROR_MSG("Missing input queue file.");
            help(argv[0]);
            return EXIT_FAILURE;
        }

        NSFileManager *fileManager = [NSFileManager defaultManager];
        NSString *inputFilePath = [NSString stringWithUTF8String:input_file];
        if ([fileManager fileExistsAtPath:inputFilePath] == NO)
        {
            ERROR_MSG("Input file %s does not exist or can't access it.", input_file);
            return EXIT_FAILURE;
        }
        
        NSData *queueBuffer = [NSData dataWithContentsOfFile:inputFilePath];
        
        /* let's switch things to C! hurray \o/ */
        char *buffer = (char*)[queueBuffer bytes];
        uint32_t buffer_size = (uint32_t)[queueBuffer length];
        
        /* first there is an header with 0x2C (44) bytes that contains some valuable information */
        DEBUG_MSG("Size of struct queue_header is %x", (int)sizeof(struct queue_header));
        if (buffer_size < sizeof(struct queue_header))
        {
            ERROR_MSG("File is too small.");
            return EXIT_FAILURE;
        }
        OUTPUT_MSG("[*] Header contents [*]");
        OUTPUT_MSG("-----------------------");
        struct queue_header *queue_header = (struct queue_header *)buffer;
        OUTPUT_MSG("[0] Expected queue file size: %d bytes", queue_header->queue_file_size);
        if (queue_header->queue_file_size != buffer_size)
        {
            ERROR_MSG("Mismatch between expected queue size and input file size: %d vs %d", queue_header->queue_file_size, buffer_size);
        }
        OUTPUT_MSG("[1] Unknown var: %d", queue_header->queue_file_size2);
        OUTPUT_MSG("[2] Unknown var: 0x%x", queue_header->unknown_var1);
        OUTPUT_MSG("[3] Unknown var: 0x%x", queue_header->unknown_var2);
        OUTPUT_MSG("[4] Unknown var: 0x%x", queue_header->unknown_var3);
        OUTPUT_MSG("[5] Data payload size: %d (0x%x) bytes", queue_header->data_size, queue_header->data_size);
        OUTPUT_MSG("[6] Unknown var: 0x%llx", queue_header->unknown_var4);
        OUTPUT_MSG("[7] Unknown var: 0x%x", queue_header->unknown_var5);
        OUTPUT_MSG("[8] Unknown var: 0x%x", queue_header->unknown_var6);
        OUTPUT_MSG("[9] Mutex name: %x", queue_header->mutex_name);
        OUTPUT_MSG("-----------------------");
        
        /* now parse the records */
        int data_offset = (int)sizeof(struct queue_header);
        /* get a pointer to buffer plus header which we already read */
        char *buffer_ptr = buffer + sizeof(struct queue_header);
        
        /* validate the first record */
        struct queue_record_header *first_record = (struct queue_record_header*)(buffer_ptr);
        DEBUG_MSG("First record id: 0x%x", first_record->record_id);
        if (first_record->record_id != 0xFFFFFFFE)
        {
            ERROR_MSG("Invalid first record!");
            return EXIT_FAILURE;
        }
        if (verbose == 1)
        {
            DEBUG_MSG("Next record id: 0x%x", first_record->next_record_id);
            DEBUG_MSG("Record data trailer size: 0x%x", first_record->record_data_size2);
            DEBUG_MSG("0x%x - 0x%x - 0x%x - cmd: 0x%x - 0x%x - 0x%x - 0x%x - 0x%x - 0x%x - 0x%x - 0x%x - 0x%x - 0x%x - 0x%x - 0x%x - 0x%x",
                      first_record->record_id,
                      first_record->index,
                      first_record->record_type,
                      first_record->cmd_id,
                      first_record->next_record_id,
                      first_record->unknown_var4,
                      first_record->unknown_var5,
                      first_record->unknown_var6,
                      first_record->timestamp,
                      first_record->unknown_var7,
                      first_record->timestamp2,
                      first_record->record_data_size,
                      first_record->record_data_size2,
                      first_record->unknown_var10,
                      first_record->unknown_var11,
                      first_record->unknown_var12);
        }
        data_offset += sizeof(struct queue_record_header) + first_record->record_data_size2;
        buffer_ptr = buffer + data_offset;
        CAST_KEY cast_key = {0};
        int cast_key_found = 0;
        unsigned char *cast_decrypt_key = NULL;
        while (data_offset < queue_header->data_size)
        {
            struct queue_record_header *next_record = (struct queue_record_header*)buffer_ptr;
            if (verbose == 1)
            {
                DEBUG_MSG("0x%x - 0x%x - 0x%x - cmd: 0x%x - 0x%x - 0x%x - 0x%x - 0x%x - 0x%x - 0x%x - 0x%x - 0x%x - 0x%x - 0x%x - 0x%x - 0x%x",
                          next_record->record_id,
                          next_record->index,
                          next_record->record_type,
                          next_record->cmd_id,
                          next_record->next_record_id,
                          next_record->unknown_var4,
                          next_record->unknown_var5,
                          next_record->unknown_var6,
                          next_record->timestamp,
                          next_record->unknown_var7,
                          next_record->timestamp2,
                          next_record->record_data_size,
                          next_record->record_data_size2,
                          next_record->unknown_var10,
                          next_record->unknown_var11,
                          next_record->unknown_var12);
            }
            /* find the decryption key
             * the sample contains code to deal with 56 bits keys but it is either legacy or something
             * we don't support that, we assume 128 bit keys
             */
            if (next_record->cmd_id == kCmdEncryptionKey && cast_key_found == 0)
            {
                DEBUG_MSG("Encryption key command found!");
                if (next_record->record_data_size != 16)
                {
                    ERROR_MSG("Encryption key size is not 128 bits!");
                    return EXIT_FAILURE;
                }
                cast_decrypt_key = (unsigned char*)(buffer_ptr + sizeof(struct queue_record_header));
                CAST_set_key(&cast_key, 16, cast_decrypt_key);
                cast_key_found = 1;
            }
            if (next_record->record_data_size > 0)
            {
                unsigned char *data_ptr = (unsigned char*)(buffer_ptr + sizeof(struct queue_record_header));
                if (verbose == 1)
                {
                    printf("Encrypted payload: ");
                    for (int i = 0; i < next_record->record_data_size; i++)
                    {
                        printf("%02x ", (unsigned char)data_ptr[i]);
                    }
                    printf("\n");
                }
                /* nothing to decrypt if it's the decryption key cmd */
                if (cast_key_found && next_record->cmd_id != kCmdEncryptionKey)
                {
                    unsigned char *out_buffer = calloc(1, next_record->record_data_size);
                    if (out_buffer == NULL)
                    {
                        ERROR_MSG("Alloc failed!");
                        return EXIT_FAILURE;
                    }
                    /*
                     * the IV is built from the decryption key and data from the encrypted string
                     * the last 4 bytes of the IV are fixed from the decryption key
                     */
                    unsigned char iv[8] = {0};
                    /* the first byte of the encrypted payload is used to build the XOR key and the first part of the IV */
                    unsigned char first_encrypted_byte = data_ptr[0];
                    /* generate the xor_key - the true encrypted payload size is one byte less and we need to advance the buffer when decrypting */
                    int xor_key = (next_record->record_data_size - 1) - first_encrypted_byte;
//                    DEBUG_MSG("Xor key is 0x%x", xor_key);
                    /* the first 4 bytes of the decryption key are XORed with the key to generate the first 4 IV bytes */
                    int xor_iv = *(int*)cast_decrypt_key ^ xor_key;
                    int *iv_ptr = (int*)iv;
                    iv_ptr[0] = xor_iv;
                    iv_ptr[1] = *(int*)(cast_decrypt_key + 4);
//                    DEBUG_MSG("First IV part is 0x%x", xor_iv);
                    /* and now we can finally see the secrets! */
                    CAST_cbc_encrypt(data_ptr+1, out_buffer, next_record->record_data_size-1, &cast_key, iv, CAST_DECRYPT);
                    printf("Decrypted payload [0x%x]: ", next_record->cmd_id);
                    for (int i = 0; i < next_record->record_data_size; i++)
                    {
                        printf("%c", out_buffer[i]);
                    }
                    printf("\n");
                    free(out_buffer);
                }
            }
            data_offset += sizeof(struct queue_record_header) + next_record->record_data_size2;
            buffer_ptr = buffer + data_offset;
        }
    }
    return 0;
}
