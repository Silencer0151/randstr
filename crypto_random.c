/*
 * Cryptographic Random String Generator
 * 
 * Description: Generates cryptographically secure random strings with high Shannon entropy
 * Date: 9/11/2025
 * 
 * Features:
 * - Cross-platform (Linux/Unix/Windows)
 * - Uses OS-provided CSPRNG (/dev/urandom, getrandom(), or BCryptGenRandom)
 * - Multiple character set modes (full ASCII, alphanumeric, numeric)
 * - Shannon entropy calculation and reporting
 * - No external dependencies beyond standard library
 * 
 * Compilation:
 *   Linux/Unix: gcc -o randstr crypto_random.c -lm
 *   Windows (MSVC): cl crypto_random.c /link bcrypt.lib
 *   Windows (MinGW): gcc -o randstr.exe crypto_random.c -lbcrypt -lm
 *          - NOTE: I personally use gcc -static -O2 -o randstr.exe crypto_random.c -lbcrypt -lm for optimization on mingw gcc
 * 
 * Usage: ./randstr <length> [mode]
 *   mode: full (default), alnum, num
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <math.h>

#ifdef _WIN32
    #include <windows.h>
    #include <bcrypt.h>
    /* pragma comment only works with MSVC, not MinGW */
    #ifdef _MSC_VER
        #pragma comment(lib, "bcrypt.lib")
    #endif
#else
    #include <unistd.h>
    #include <fcntl.h>
    #include <sys/random.h>
#endif

// Character sets for different modes
const char CHARSET_FULL[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}|;:,.<>?";
const char CHARSET_ALNUM[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const char CHARSET_NUM[] = "0123456789";

// Get cryptographically secure random bytes
int get_random_bytes(unsigned char *buffer, size_t length) {
#ifdef _WIN32
    // Windows: Use BCryptGenRandom
    NTSTATUS status = BCryptGenRandom(NULL, buffer, (ULONG)length, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return (status == 0) ? 0 : -1;
#else
    // Linux/Unix: Try getrandom first, fall back to /dev/urandom
    #ifdef __linux__
        // getrandom is available on Linux 3.17+
        ssize_t result = getrandom(buffer, length, 0);
        if (result == (ssize_t)length) {
            return 0;
        }
    #endif
    
    // Fallback to /dev/urandom
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        perror("Failed to open /dev/urandom");
        return -1;
    }
    
    size_t bytes_read = 0;
    while (bytes_read < length) {
        ssize_t result = read(fd, buffer + bytes_read, length - bytes_read);
        if (result < 0) {
            if (errno == EINTR) continue;
            close(fd);
            perror("Failed to read from /dev/urandom");
            return -1;
        }
        bytes_read += result;
    }
    
    close(fd);
    return 0;
#endif
}

// Generate random string with specified character set
char* generate_random_string(size_t length, const char *charset) {
    size_t charset_size = strlen(charset);
    
    // Allocate memory for the string (+1 for null terminator)
    char *result = malloc(length + 1);
    if (!result) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }
    
    // Allocate buffer for random bytes
    unsigned char *random_bytes = malloc(length);
    if (!random_bytes) {
        fprintf(stderr, "Memory allocation failed\n");
        free(result);
        return NULL;
    }
    
    // Get cryptographically secure random bytes
    if (get_random_bytes(random_bytes, length) != 0) {
        fprintf(stderr, "Failed to generate random bytes\n");
        free(random_bytes);
        free(result);
        return NULL;
    }
    
    // Convert random bytes to characters from the charset
    for (size_t i = 0; i < length; i++) {
        // Use modulo bias reduction for uniform distribution
        // For small charsets, the bias is negligible
        result[i] = charset[random_bytes[i] % charset_size];
    }
    
    result[length] = '\0';
    free(random_bytes);
    return result;
}

// Calculate Shannon entropy of a string
double calculate_shannon_entropy(const char *str) {
    int freq[256] = {0};
    size_t len = strlen(str);
    
    // Count character frequencies
    for (size_t i = 0; i < len; i++) {
        freq[(unsigned char)str[i]]++;
    }
    
    // Calculate entropy
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / len;
            entropy -= p * (log(p) / log(2.0));
        }
    }
    
    return entropy;
}

void print_usage(const char *program_name) {
    printf("Usage: %s <length> [mode]\n", program_name);
    printf("  length: Length of the random string to generate\n");
    printf("  mode (optional):\n");
    printf("    full   - All printable ASCII including special chars (default)\n");
    printf("    alnum  - Alphanumeric only (A-Z, a-z, 0-9)\n");
    printf("    num    - Numbers only (0-9)\n");
    printf("\nExample: %s 32 full\n", program_name);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    // Parse length argument
    char *endptr;
    long length = strtol(argv[1], &endptr, 10);
    if (*endptr != '\0' || length <= 0 || length > 1000000) {
        fprintf(stderr, "Error: Invalid length. Must be a positive integer (max 1000000)\n");
        return 1;
    }
    
    // Determine character set based on mode
    const char *charset = CHARSET_FULL;
    const char *mode_name = "full";
    
    if (argc >= 3) {
        if (strcmp(argv[2], "alnum") == 0) {
            charset = CHARSET_ALNUM;
            mode_name = "alphanumeric";
        } else if (strcmp(argv[2], "num") == 0) {
            charset = CHARSET_NUM;
            mode_name = "numeric";
        } else if (strcmp(argv[2], "full") != 0) {
            fprintf(stderr, "Error: Invalid mode. Use 'full', 'alnum', or 'num'\n");
            return 1;
        }
    }
    
    // Generate the random string
    char *random_string = generate_random_string((size_t)length, charset);
    if (!random_string) {
        return 1;
    }
    
    // Output the string
    printf("%s\n", random_string);
    
    // Calculate and display entropy information (to stderr so it doesn't interfere with piping)
    double entropy = calculate_shannon_entropy(random_string);
    double max_entropy = log(strlen(charset)) / log(2.0);
    
    fprintf(stderr, "\n--- Entropy Information ---\n");
    fprintf(stderr, "Mode: %s (%zu characters)\n", mode_name, strlen(charset));
    fprintf(stderr, "String length: %ld\n", length);
    fprintf(stderr, "Shannon entropy: %.2f bits/char\n", entropy);
    fprintf(stderr, "Maximum possible: %.2f bits/char\n", max_entropy);
    fprintf(stderr, "Total entropy: %.2f bits\n", entropy * length);
    fprintf(stderr, "Efficiency: %.1f%%\n", (entropy / max_entropy) * 100);
    
    free(random_string);
    return 0;
}