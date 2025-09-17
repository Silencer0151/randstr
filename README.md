# randstr

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
