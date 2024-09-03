#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "risc_v_disassembler.h"

int main(int argc, char** argv) {
    if (argc < 3) {
        printf("Usage: %s <hex_file> <rv32/rv64/rv128>\n", argv[0]);
        goto error;
    }

    if ((strcmp(argv[2], "rv32") != 0) && (strcmp(argv[2], "rv64") != 0) && (strcmp(argv[2], "rv128") != 0)) {
        printf("Usage: %s <hex_file> <rv32/rv64/rv128>\n", argv[0]);
        goto error;
    }

    FILE *input;
    if ((input = fopen(argv[1], "rb")) == NULL) {
        printf("Can't open file.\n");
        goto error;
    }

    hex_string h_str;
    //MAKE SURE
    h_str.cur_ptr = 0;

    //FIND START OFFSET
    uint16_t r_cs = 0;
    uint16_t r_ip = 0;
    while ((h_str.legit = fgetc(input)) == ':')
    {
        h_str.length = fgetc_hex(input);
        h_str.offset = fgetc_hex(input) << 8;
        h_str.offset += fgetc_hex(input);
        h_str.flags = fgetc_hex(input);
        fgets_hex(h_str.data, h_str.length, input);
        h_str.checksum = fgetc_hex(input);
        // IGNORE '\n'
        while (fgetc(input) != 0x0a);
        if (h_str.flags == 0x03) {
            r_cs = h_str.data[0] << 8;
            r_cs += h_str.data[1];
            r_ip = h_str.data[2] << 8;
            r_ip += h_str.data[3];
            fsetpos(input, 0);
            break;
        }
    }
    //

    //

    /*char ch;
    char buf[64];
    uint8_t buf_p = 0;
    while ((ch = getc(input)) != EOF)
    {
        printf("%c", ch);
    }*/

    /*
    hex_string h_str;
    while ((h_str.legit = fgetc(input)) == ':')
    {
        h_str.length = fgetc_hex(input);
        h_str.offset = fgetc_hex(input) << 8;
        h_str.offset += fgetc_hex(input);
        h_str.flags = fgetc_hex(input);
        fgets_hex(h_str.data, h_str.length, input);
        h_str.checksum = fgetc_hex(input);
        // IGNORE '\n'
        while (fgetc(input) != 0x0a);
    }
    */

    fclose(input);
    return 0;

    error_while_file_read:
    fclose(input);
    error:
    return 1;
}

// GET HEX BYTE FROM .HEX FILE STRING
uint8_t fgetc_hex(FILE *file) {
    uint8_t hex = 0;
    hex = str_byte_to_hex(fgetc(file)) << 4;
    hex += str_byte_to_hex(fgetc(file));
    return hex;
}

// GET HEX STRING FROM .HEX FILE STRING
uint8_t fgets_hex(uint8_t* buf, size_t num, FILE *file) {
    for (size_t i = 0; i < num; i++) {
        *buf = fgetc_hex(file);
        buf++;
    }
}

// TRANSLATE .HEX FILE STRING BYTE(2 char) TO HEX FORMAT
uint8_t str_byte_to_hex(uint8_t str_byte) {
    if ((0x30 <= str_byte) && (str_byte <= 0x39)) {
        return str_byte - 0x30;
    } else if ((0x41 <= str_byte) && (str_byte <= 0x46)) {
        return str_byte - 0x37;
    } else if ((0x61 <= str_byte) && (str_byte <= 0x66)) {
        return str_byte - 0x57;
    }
}

uint8_t *get_bytes_from_hex_string(hex_string *h_str, size_t count) {
    if (count > 32) { // DON'T WANNA MAKE TO BIG
        goto error;
    }

    uint8_t *return_mas = NULL;
    return_mas = calloc(count, sizeof(uint8_t));
    if (return_mas == NULL) {
        goto error;
    }
    
    return 0;

    error:
    return 1;
}