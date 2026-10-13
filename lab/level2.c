/*
 * Nivel 2 — Suprascrierea adresei de retur: preluarea controlului.
 *
 * Compilare (vulnerabil):
 *   gcc -g -O0 -m32 -fno-stack-protector -no-pie -fno-pic -o level2 level2.c
 *
 * Compilare (protejat, pentru comparatie):
 *   gcc -O0 -m32 -o level2_prot level2.c
 *
 * Offsetul pana la adresa de retur este 76 (masurat in gdb cu un cyclic pattern).
 */
#include <stdio.h>
#include <unistd.h>

void vuln(void) {
    char buffer[64];
    read(0, buffer, 512);     /* citim 512 octeti intr-un buffer de 64 */
}

int main(void) {
    vuln();
    puts("normal return from vuln()");
    return 0;
}
