#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SO File Decryptor & Decoder Tool
Author: Pro Edition
Version: 1.0
"""

import os
import sys
import hashlib
import struct
import base64
import subprocess
from pathlib import Path

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    from capstone import Cs, CS_ARCH_ARM, CS_ARCH_ARM64, CS_ARCH_X86, CS_MODE_ARM, CS_MODE_64, CS_MODE_32
    import lief
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import track
    from rich import box
    from colorama import Fore, Style, init
    from Crypto.Cipher import AES, XOR
except ImportError as e:
    print(f"[!] Missing module: {e}")
    print("[*] Run: bash install.sh")
    sys.exit(1)

init(autoreset=True)
console = Console()

# ═══════════════ BANNER ═══════════════
BANNER = r"""
[bold cyan]
 ███████╗ ██████╗     ██████╗ ███████╗ ██████╗██████╗ ██╗   ██╗██████╗ ████████╗
 ██╔════╝██╔═══██╗    ██╔══██╗██╔════╝██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝
 ███████╗██║   ██║    ██║  ██║█████╗  ██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   
 ╚════██║██║   ██║    ██║  ██║██╔══╝  ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   
 ███████║╚██████╔╝    ██████╔╝███████╗╚██████╗██║  ██║   ██║   ██║        ██║   
 ╚══════╝ ╚═════╝     ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝   
[/bold cyan]
[bold yellow]              ⚡ Professional .SO File Analyzer & Decryptor ⚡[/bold yellow]
[bold green]                       Author: Pro Edition | v1.0[/bold green]
"""

# ═══════════════ CORE CLASS ═══════════════
class SODecryptor:
    def __init__(self, filepath):
        self.filepath = filepath
        self.filename = os.path.basename(filepath)
        self.data = None
        self.elf = None
        self.load()

    def load(self):
        if not os.path.exists(self.filepath):
            console.print(f"[bold red][✗] File not found: {self.filepath}[/bold red]")
            sys.exit(1)
        with open(self.filepath, "rb") as f:
            self.data = f.read()
        try:
            self.elf = lief.parse(self.filepath)
        except Exception as e:
            console.print(f"[yellow][!] LIEF parse warning: {e}[/yellow]")

    # ───── 1. File Info ─────
    def file_info(self):
        size = os.path.getsize(self.filepath)
        md5 = hashlib.md5(self.data).hexdigest()
        sha1 = hashlib.sha1(self.data).hexdigest()
        sha256 = hashlib.sha256(self.data).hexdigest()

        table = Table(title="📄 File Information", box=box.DOUBLE_EDGE, style="cyan")
        table.add_column("Property", style="yellow", no_wrap=True)
        table.add_column("Value", style="white")
        table.add_row("Filename", self.filename)
        table.add_row("Path", self.filepath)
        table.add_row("Size", f"{size:,} bytes ({size/1024:.2f} KB)")
        table.add_row("MD5", md5)
        table.add_row("SHA1", sha1)
        table.add_row("SHA256", sha256)

        if self.elf:
            table.add_row("Architecture", str(self.elf.header.machine_type).split(".")[-1])
            table.add_row("Entry Point", hex(self.elf.entrypoint))
            table.add_row("Type", str(self.elf.header.file_type).split(".")[-1])

        console.print(table)

    # ───── 2. ELF Header ─────
    def elf_header(self):
        try:
            with open(self.filepath, "rb") as f:
                elffile = ELFFile(f)
                h = elffile.header
                table = Table(title="🧩 ELF Header", box=box.ROUNDED, style="magenta")
                table.add_column("Field", style="yellow")
                table.add_column("Value", style="green")
                for key, val in h.items():
                    table.add_row(str(key), str(val))
                console.print(table)
        except Exception as e:
            console.print(f"[red][✗] {e}[/red]")

    # ───── 3. Sections ─────
    def list_sections(self):
        if not self.elf:
            return
        table = Table(title="📚 ELF Sections", box=box.HEAVY_EDGE, style="cyan")
        table.add_column("#", style="yellow")
        table.add_column("Name", style="green")
        table.add_column("Type", style="magenta")
        table.add_column("Size", style="white")
        table.add_column("Offset", style="cyan")
        for i, sec in enumerate(self.elf.sections):
            table.add_row(str(i), sec.name, str(sec.type).split(".")[-1],
                          str(sec.size), hex(sec.offset))
        console.print(table)

    # ───── 4. Symbols ─────
    def list_symbols(self):
        if not self.elf:
            return
        table = Table(title="🔣 Exported Symbols", box=box.SIMPLE, style="green")
        table.add_column("Symbol", style="cyan")
        table.add_column("Address", style="yellow")
        table.add_column("Size", style="white")
        count = 0
        for sym in self.elf.exported_symbols:
            table.add_row(sym.name[:60], hex(sym.value), str(sym.size))
            count += 1
            if count >= 50:
                break
        console.print(table)
        console.print(f"[green]Total exported symbols: {len(self.elf.exported_symbols)}[/green]")

    # ───── 5. Strings ─────
    def extract_strings(self, min_len=4):
        console.print("[cyan][*] Extracting printable strings...[/cyan]")
        result = []
        current = b""
        for byte in self.data:
            if 32 <= byte < 127:
                current += bytes([byte])
            else:
                if len(current) >= min_len:
                    result.append(current.decode(errors='ignore'))
                current = b""
        out_file = f"{self.filename}_strings.txt"
        with open(out_file, "w") as f:
            f.write("\n".join(result))
        console.print(f"[green][✓] Extracted {len(result)} strings → {out_file}[/green]")

    # ───── 6. XOR Decrypt ─────
    def xor_decrypt(self, key):
        key_bytes = key.encode() if isinstance(key, str) else key
        decrypted = bytearray()
        for i, b in enumerate(self.data):
            decrypted.append(b ^ key_bytes[i % len(key_bytes)])
        out = f"{self.filename}_xor_decrypted.so"
        with open(out, "wb") as f:
            f.write(decrypted)
        console.print(f"[green][✓] XOR decrypted → {out}[/green]")

    # ───── 7. AES Decrypt ─────
    def aes_decrypt(self, key, iv=None):
        try:
            key_b = key.encode().ljust(32, b'\0')[:32]
            iv_b = iv.encode().ljust(16, b'\0')[:16] if iv else b'\0' * 16
            cipher = AES.new(key_b, AES.MODE_CBC, iv_b)
            padded = self.data + b'\0' * (16 - len(self.data) % 16)
            decrypted = cipher.decrypt(padded)
            out = f"{self.filename}_aes_decrypted.so"
            with open(out, "wb") as f:
                f.write(decrypted)
            console.print(f"[green][✓] AES decrypted → {out}[/green]")
        except Exception as e:
            console.print(f"[red][✗] AES Error: {e}[/red]")

    # ───── 8. Base64 Decode ─────
    def base64_decode(self):
        try:
            decoded = base64.b64decode(self.data)
            out = f"{self.filename}_b64_decoded.so"
            with open(out, "wb") as f:
                f.write(decoded)
            console.print(f"[green][✓] Base64 decoded → {out}[/green]")
        except Exception as e:
            console.print(f"[red][✗] {e}[/red]")

    # ───── 9. Disassemble ─────
    def disassemble(self, limit=100):
        if not self.elf:
            return
        try:
            text_section = self.elf.get_section(".text")
            if not text_section:
                console.print("[red][✗] No .text section[/red]")
                return
            code = bytes(text_section.content)
            arch = str(self.elf.header.machine_type)

            if "AARCH64" in arch:
                md = Cs(CS_ARCH_ARM64, CS_MODE_64)
            elif "ARM" in arch:
                md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
            elif "x86_64" in arch:
                md = Cs(CS_ARCH_X86, CS_MODE_64)
            else:
                md = Cs(CS_ARCH_X86, CS_MODE_32)

            out_file = f"{self.filename}_disasm.txt"
            with open(out_file, "w") as f:
                count = 0
                for inst in md.disasm(code, text_section.virtual_address):
                    line = f"0x{inst.address:x}:\t{inst.mnemonic}\t{inst.op_str}"
                    f.write(line + "\n")
                    if count < limit:
                        console.print(f"[cyan]{line}[/cyan]")
                    count += 1
            console.print(f"[green][✓] Disassembly saved → {out_file} ({count} instructions)[/green]")
        except Exception as e:
            console.print(f"[red][✗] {e}[/red]")

    # ───── 10. Entropy Analysis ─────
    def entropy(self):
        import math
        if not self.data:
            return
        freq = [0] * 256
        for b in self.data:
            freq[b] += 1
        total = len(self.data)
        ent = -sum((c/total) * math.log2(c/total) for c in freq if c > 0)
        status = "🔒 Encrypted/Packed" if ent > 7.0 else "📄 Normal"
        panel = Panel(
            f"[yellow]Entropy:[/yellow] [bold green]{ent:.4f}[/bold green] / 8.0\n"
            f"[yellow]Status:[/yellow] [bold]{status}[/bold]",
            title="📊 Entropy Analysis", style="cyan"
        )
        console.print(panel)


# ═══════════════ MENU ═══════════════
def menu():
    console.print(Panel.fit(
        "[bold yellow]1.[/bold yellow] File Information\n"
        "[bold yellow]2.[/bold yellow] ELF Header Details\n"
        "[bold yellow]3.[/bold yellow] List Sections\n"
        "[bold yellow]4.[/bold yellow] Exported Symbols\n"
        "[bold yellow]5.[/bold yellow] Extract Strings\n"
        "[bold yellow]6.[/bold yellow] XOR Decrypt\n"
        "[bold yellow]7.[/bold yellow] AES Decrypt\n"
        "[bold yellow]8.[/bold yellow] Base64 Decode\n"
        "[bold yellow]9.[/bold yellow] Disassemble (.text)\n"
        "[bold yellow]10.[/bold yellow] Entropy Analysis\n"
        "[bold yellow]11.[/bold yellow] Run All Analysis\n"
        "[bold red]0.[/bold red] Exit",
        title="[bold cyan]⚙️  MAIN MENU[/bold cyan]",
        border_style="green"
    ))


def main():
    os.system("clear")
    console.print(BANNER)

    filepath = console.input("[bold yellow]📂 Enter .so file path: [/bold yellow]").strip()
    if not filepath:
        console.print("[red][✗] No file provided[/red]")
        return

    tool = SODecryptor(filepath)

    while True:
        menu()
        choice = console.input("[bold cyan]➤ Select option: [/bold cyan]").strip()

        if choice == "1": tool.file_info()
        elif choice == "2": tool.elf_header()
        elif choice == "3": tool.list_sections()
        elif choice == "4": tool.list_symbols()
        elif choice == "5":
            ml = console.input("[yellow]Min length (default 4): [/yellow]") or "4"
            tool.extract_strings(int(ml))
        elif choice == "6":
            k = console.input("[yellow]XOR Key: [/yellow]")
            tool.xor_decrypt(k)
        elif choice == "7":
            k = console.input("[yellow]AES Key: [/yellow]")
            iv = console.input("[yellow]IV (optional): [/yellow]")
            tool.aes_decrypt(k, iv if iv else None)
        elif choice == "8": tool.base64_decode()
        elif choice == "9":
            lim = console.input("[yellow]Show lines (default 100): [/yellow]") or "100"
            tool.disassemble(int(lim))
        elif choice == "10": tool.entropy()
        elif choice == "11":
            tool.file_info()
            tool.elf_header()
            tool.list_sections()
            tool.list_symbols()
            tool.entropy()
            tool.extract_strings()
        elif choice == "0":
            console.print("[bold green]👋 Goodbye![/bold green]")
            break
        else:
            console.print("[red][✗] Invalid choice[/red]")

        console.input("\n[dim]Press Enter to continue...[/dim]")
        os.system("clear")
        console.print(BANNER)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold red][!] Interrupted by user[/bold red]")
        sys.exit(0)
