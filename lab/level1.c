/*
 * Nivel 1 — Overflow simplu: suprascrierea unei variabile locale.
 *
 * Compilare:
 *   gcc -g -O0 -m32 -fno-stack-protector -no-pie -fno-pic -o level1 level1.c
 *
 * Rulare:
 *   ./level1 $(python3 -c 'print("A"*16)')   -> authenticated = 0
 *   ./level1 $(python3 -c 'print("A"*17)')   -> authenticated = 65
 */
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    volatile int authenticated = 0;
    char buffer[16];

    strcpy(buffer, argv[1]);          /* nicio verificare de dimensiune */

    if (authenticated) {
        printf("Access granted! authenticated=%d\n", authenticated);
    } else {
        printf("Access denied. authenticated=%d\n", authenticated);
    }
    return 0;
}
