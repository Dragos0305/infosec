# ============================================================================
# Makefile pentru laboratorul de Buffer Overflow
#
# Fiecare tinta reproduce comanda de compilare din docs/buffer-overflow.md.
# Binarele sunt INTENTIONAT vulnerabile si sunt doar pentru laborator (VM).
#
# Fiecare nivel poate fi compilat pe doua arhitecturi:
#   - x86 (32 de biti, -m32)  -> necesita gcc-multilib
#   - x86-64 (64 de biti, -static, aduce gadget-uri ROP)
#
# Necesita gcc cu suport 32 de biti pentru tintele x32:
#   sudo apt install -y gcc gcc-multilib
#
# Tinte utile:
#   make            / make all   - compileaza toate nivelurile, ambele arhitecturi
#   make x32                     - doar variantele pe 32 de biti
#   make x64                     - doar variantele pe 64 de biti
#   make level1    / level1_64   - Nivel 1 (overflow variabila locala)
#   make level2    / level2_64   - Nivel 2 (adresa de retur)
#   make level2_prot             - Nivel 2 cu protectiile implicite (demo aparari)
#   make ret2win   / ret2win64   - Nivel 3 (x86-32) / Nivel 4 (x86-64 static)
#   make check                   - ruleaza checksec pe binarele produse
#   make disable-aslr            - dezactiveaza ASLR (necesita sudo, doar in VM)
#   make clean                   - sterge binarele si fisierele auxiliare
# ============================================================================

CC      := gcc

# Flag-uri comune vulnerabile, independente de arhitectura.
# -w: dezactivam avertismentele compilatorului - buffer overflow-ul este
#     intentionat, iar avertismentele (ex. citire peste dimensiunea buffer-ului)
#     doar ar polua iesirea compilarii.
VCOMMON := -g -O0 -fno-stack-protector -no-pie -fno-pic -w
# x86 (32 de biti): link dinamic clasic.
V32     := $(VCOMMON) -m32
# x86-64 (64 de biti): link static, ca sa avem gadget-uri ROP in binar.
V64     := $(VCOMMON) -static

# Binarele pe 32 de biti pastreaza numele folosite in laborator (fara sufix).
BIN32   := level1 level2 ret2win
# Binarele pe 64 de biti: sufix _64, cu exceptia lui ret2win64 (numele din doc).
BIN64   := level1_64 level2_64 ret2win64

.PHONY: all x32 x64 check disable-aslr clean help
.DEFAULT_GOAL := all

all: x32 x64 level2_prot
x32: $(BIN32)
x64: $(BIN64)

# --- x86 (32 de biti) --------------------------------------------------------
level1: level1.c
	$(CC) $(V32) -o $@ $<

level2: level2.c
	$(CC) $(V32) -o $@ $<

ret2win: ret2win.c
	$(CC) $(V32) -o $@ $<

# Acelasi cod ca level2, dar cu protectiile implicite (canary, PIE, NX).
# Folosit in sectiunea "apararile" ca sa aratam cum e blocat atacul.
level2_prot: level2.c
	$(CC) -O0 -m32 -w -o $@ $<

# --- x86-64 (64 de biti, static) ---------------------------------------------
level1_64: level1.c
	$(CC) $(V64) -o $@ $<

level2_64: level2.c
	$(CC) $(V64) -o $@ $<

ret2win64: ret2win.c
	$(CC) $(V64) -o $@ $<

# --- Utilitare ---------------------------------------------------------------
check: $(BIN32) $(BIN64)
	@command -v checksec >/dev/null 2>&1 || { \
		echo "checksec nu este instalat (pip install checksec.py sau apt install checksec)"; exit 1; }
	@for b in $(BIN32) $(BIN64); do \
		echo "=== $$b ==="; \
		checksec --file=$$b || checksec --file "$$b"; \
		echo; \
	done

# Dezactiveaza ASLR ca adresele sa fie stabile in gdb. DOAR intr-o masina virtuala.
disable-aslr:
	echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

clean:
	rm -f $(BIN32) $(BIN64) level2_prot *.o payload.bin pattern.bin core core.*

help:
	@sed -n '1,30p' Makefile
