/*
 * Nivel 3 (x86-32) si Nivel 4 (x86-64) — ret2win.
 *
 * Programul contine o functie win() care nu este apelata niciodata in mod
 * normal. Prin overflow fortam executia ei cu argumente alese de noi.
 *
 * Compilare x86-32 (Nivel 3):
 *   gcc -g -O0 -m32 -fno-stack-protector -no-pie -fno-pic -o ret2win ret2win.c
 *
 * Compilare x86-64 cu linkare statica (Nivel 4, aduce gadget-uri ROP):
 *   gcc -g -O0 -no-pie -fno-pic -fno-stack-protector -static -o ret2win64 ret2win.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* Functia secreta. Nu este apelata niciodata in mod normal. */
void win(int magic, int key) {
    if (magic == 0xdeadbeef && key == 0x1337c0de) {
        puts("[+] win() with correct arguments - control hijacked!");
        exit(0);
    }
    printf("[-] win() called, but magic=%#x key=%#x\n", magic, key);
}

void vuln(void) {
    char buffer[64];
    read(0, buffer, 512);
}

int main(void) {
    vuln();
    puts("normal return from vuln()");
    return 0;
}
