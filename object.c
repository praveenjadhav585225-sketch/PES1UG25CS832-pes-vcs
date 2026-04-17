// object.c — Content-addressable object store
//
// Every piece of data (file contents, directory listings, commits) is stored
// as an "object" named by its SHA-256 hash. Objects are stored under
// .pes/objects/XX/YYYYYY... where XX is the first two hex characters of the
// hash (directory sharding).
//
// PROVIDED functions: compute_hash, object_path, object_exists, hash_to_hex, hex_to_hash
// TODO functions:     object_write, object_read

#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>

// ─── PROVIDED ────────────────────────────────────────────────────────────────

void hash_to_hex(const ObjectID *id, char *hex_out) {
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(hex_out + i * 2, "%02x", id->hash[i]);
    }
    hex_out[HASH_HEX_SIZE] = '\0';
}

int hex_to_hash(const char *hex, ObjectID *id_out) {
    if (strlen(hex) < HASH_HEX_SIZE) return -1;
    for (int i = 0; i < HASH_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        id_out->hash[i] = (uint8_t)byte;
    }
    return 0;
}

void compute_hash(const void *data, size_t len, ObjectID *id_out) {
    unsigned int hash_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, id_out->hash, &hash_len);
    EVP_MD_CTX_free(ctx);
}

// Get the filesystem path where an object should be stored.
// Format: .pes/objects/XX/YYYYYYYY...
// The first 2 hex chars form the shard directory; the rest is the filename.
void object_path(const ObjectID *id, char *path_out, size_t path_size) {
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    snprintf(path_out, path_size, "%s/%.2s/%s", OBJECTS_DIR, hex, hex + 2);
}

int object_exists(const ObjectID *id) {
    char path[512];
    object_path(id, path, sizeof(path));
    return access(path, F_OK) == 0;
}

// ─── TODO: Implement these ──────────────────────────────────────────────────

// Write an object to the store.
//
// Object format on disk:
//   "<type> <size>\0<data>"
//   where <type> is "blob", "tree", or "commit"
//   and <size> is the decimal string of the data length
//
// Steps:
//   1. Build the full object: header ("blob 16\0") + data
//   2. Compute SHA-256 hash of the FULL object (header + data)
//   3. Check if object already exists (deduplication) — if so, just return success
//   4. Create shard directory (.pes/objects/XX/) if it doesn't exist
//   5. Write to a temporary file in the same shard directory
//   6. fsync() the temporary file to ensure data reaches disk
//   7. rename() the temp file to the final path (atomic on POSIX)
//   8. Open and fsync() the shard directory to persist the rename
//   9. Store the computed hash in *id_out

// HINTS - Useful syscalls and functions for this phase:
//   - sprintf / snprintf : formatting the header string
//   - compute_hash       : hashing the combined header + data
//   - object_exists      : checking for deduplication
//   - mkdir              : creating the shard directory (use mode 0755)
//   - open, write, close : creating and writing to the temp file
//                          (Use O_CREAT | O_WRONLY | O_TRUNC, mode 0644)
//   - fsync              : flushing the file descriptor to disk
//   - rename             : atomically moving the temp file to the final path
//

//
// Returns 0 on success, -1 on error.
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {
    if (id_out == NULL) return -1;
    if (len > 0 && data == NULL) return -1;

    const char *type_str;
    switch (type) {
        case OBJ_BLOB: type_str = "blob"; break;
        case OBJ_TREE: type_str = "tree"; break;
        case OBJ_COMMIT: type_str = "commit"; break;
        default: return -1;
    }

    char header[64];
    int header_chars = snprintf(header, sizeof(header), "%s %zu", type_str, len);
    if (header_chars < 0) return -1;
    size_t header_len = (size_t)header_chars + 1; // include NUL separator
    if (header_len > sizeof(header)) return -1;

    if (header_len > SIZE_MAX - len) return -1;
    size_t object_len = header_len + len;

    unsigned char *object_buf = malloc(object_len);
    if (object_buf == NULL) return -1;
    memcpy(object_buf, header, header_len);
    if (len > 0) memcpy(object_buf + header_len, data, len);

    compute_hash(object_buf, object_len, id_out);

    if (object_exists(id_out)) {
        free(object_buf);
        return 0;
    }

    char final_path[512];
    object_path(id_out, final_path, sizeof(final_path));

    char shard_dir[512];
    strncpy(shard_dir, final_path, sizeof(shard_dir) - 1);
    shard_dir[sizeof(shard_dir) - 1] = '\0';
    char *slash = strrchr(shard_dir, '/');
    if (slash == NULL) {
        free(object_buf);
        return -1;
    }
    *slash = '\0';

    if (mkdir(shard_dir, 0755) == -1 && errno != EEXIST) {
        free(object_buf);
        return -1;
    }

    char temp_path[640];
    int temp_chars = snprintf(temp_path, sizeof(temp_path), "%s/.tmp-%ld", shard_dir, (long)getpid());
    if (temp_chars < 0 || (size_t)temp_chars >= sizeof(temp_path)) {
        free(object_buf);
        return -1;
    }

    int fd = open(temp_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) {
        free(object_buf);
        return -1;
    }

    size_t written = 0;
    while (written < object_len) {
        ssize_t n = write(fd, object_buf + written, object_len - written);
        if (n < 0) {
            close(fd);
            unlink(temp_path);
            free(object_buf);
            return -1;
        }
        written += (size_t)n;
    }

    if (fsync(fd) == -1) {
        close(fd);
        unlink(temp_path);
        free(object_buf);
        return -1;
    }

    if (close(fd) == -1) {
        unlink(temp_path);
        free(object_buf);
        return -1;
    }

    if (rename(temp_path, final_path) == -1) {
        unlink(temp_path);
        free(object_buf);
        return -1;
    }

    int dfd = open(shard_dir, O_RDONLY | O_DIRECTORY);
    if (dfd < 0) {
        free(object_buf);
        return -1;
    }
    if (fsync(dfd) == -1) {
        close(dfd);
        free(object_buf);
        return -1;
    }
    if (close(dfd) == -1) {
        free(object_buf);
        return -1;
    }

    free(object_buf);
    return 0;
}

// Read an object from the store.
//
// Steps:
//   1. Build the file path from the hash using object_path()
//   2. Open and read the entire file
//   3. Parse the header to extract the type string and size
//   4. Verify integrity: recompute the SHA-256 of the file contents
//      and compare to the expected hash (from *id). Return -1 if mismatch.
//   5. Set *type_out to the parsed ObjectType
//   6. Allocate a buffer, copy the data portion (after the \0), set *data_out and *len_out
//
// HINTS - Useful syscalls and functions for this phase:
//   - object_path        : getting the target file path
//   - fopen, fread, fseek: reading the file into memory
//   - memchr             : safely finding the '\0' separating header and data
//   - strncmp            : parsing the type string ("blob", "tree", "commit")
//   - compute_hash       : re-hashing the read data for integrity verification
//   - memcmp             : comparing the computed hash against the requested hash
//   - malloc, memcpy     : allocating and returning the extracted data
//
// The caller is responsible for calling free(*data_out).
// Returns 0 on success, -1 on error (file not found, corrupt, etc.).
int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {
    if (id == NULL || type_out == NULL || data_out == NULL || len_out == NULL) return -1;

    char path[512];
    object_path(id, path, sizeof(path));

    FILE *f = fopen(path, "rb");
    if (f == NULL) return -1;

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return -1;
    }
    long file_size_l = ftell(f);
    if (file_size_l < 0) {
        fclose(f);
        return -1;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return -1;
    }

    size_t file_size = (size_t)file_size_l;
    if ((long)file_size != file_size_l) {
        fclose(f);
        return -1;
    }

    unsigned char *file_buf = malloc(file_size);
    if (file_buf == NULL) {
        fclose(f);
        return -1;
    }

    if (file_size > 0 && fread(file_buf, 1, file_size, f) != file_size) {
        free(file_buf);
        fclose(f);
        return -1;
    }
    fclose(f);

    char *nul = memchr(file_buf, '\0', file_size);
    if (nul == NULL) {
        free(file_buf);
        return -1;
    }

    size_t header_len = (size_t)(nul - (char *)file_buf);
    char *sp = memchr(file_buf, ' ', header_len);
    if (sp == NULL) {
        free(file_buf);
        return -1;
    }

    size_t type_len = (size_t)(sp - (char *)file_buf);
    size_t size_str_len = header_len - type_len - 1;
    if (type_len == 0 || size_str_len == 0 || type_len >= 16 || size_str_len >= 32) {
        free(file_buf);
        return -1;
    }

    char type_str[16];
    memcpy(type_str, file_buf, type_len);
    type_str[type_len] = '\0';

    ObjectType parsed_type;
    if (strcmp(type_str, "blob") == 0) parsed_type = OBJ_BLOB;
    else if (strcmp(type_str, "tree") == 0) parsed_type = OBJ_TREE;
    else if (strcmp(type_str, "commit") == 0) parsed_type = OBJ_COMMIT;
    else {
        free(file_buf);
        return -1;
    }

    char size_str[32];
    memcpy(size_str, sp + 1, size_str_len);
    size_str[size_str_len] = '\0';

    errno = 0;
    char *endptr = NULL;
    unsigned long long parsed_len_ull = strtoull(size_str, &endptr, 10);
    if (errno != 0 || endptr == size_str || *endptr != '\0') {
        free(file_buf);
        return -1;
    }
    if (parsed_len_ull > SIZE_MAX) {
        free(file_buf);
        return -1;
    }
    size_t parsed_len = (size_t)parsed_len_ull;

    if (header_len + 1 > file_size) {
        free(file_buf);
        return -1;
    }

    size_t payload_len = file_size - header_len - 1;
    if (payload_len != parsed_len) {
        free(file_buf);
        return -1;
    }

    ObjectID computed;
    compute_hash(file_buf, file_size, &computed);
    if (memcmp(computed.hash, id->hash, HASH_SIZE) != 0) {
        free(file_buf);
        return -1;
    }

    void *payload = malloc(payload_len == 0 ? 1 : payload_len);
    if (payload == NULL) {
        free(file_buf);
        return -1;
    }
    if (payload_len > 0) memcpy(payload, file_buf + header_len + 1, payload_len);

    *type_out = parsed_type;
    *data_out = payload;
    *len_out = payload_len;

    free(file_buf);
    return 0;
}
