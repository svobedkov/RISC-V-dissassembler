typedef struct {
    uint8_t legit;
    uint8_t length;
    uint16_t offset;
    uint8_t flags;
    uint8_t data[16];
    uint8_t checksum;
    //
    uint8_t cur_ptr;
} hex_string;

uint8_t fgetc_hex(FILE *file);
uint8_t fgets_hex(uint8_t* buf, size_t num, FILE *file);
uint8_t str_byte_to_hex(uint8_t str_byte);

uint8_t *get_bytes_from_hex_string(hex_string *h_str, size_t count);