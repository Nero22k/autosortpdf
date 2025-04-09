import os
import csv
import shutil
import re
import pymupdf
from keybert import KeyBERT
from tabulate import tabulate
from collections import defaultdict
import time

# --- Configuration ---
# !!! IMPORTANT: SET THIS TO THE ACTUAL PATH OF YOUR PDF DIRECTORY !!!
PDF_SOURCE_DIR = "./my_pdfs"

OUTPUT_CSV = "pdf_keywords.csv" # CSV output file
DEFAULT_CATEGORY = "Uncategorized"
PAGES_TO_SCAN = 10 # Number of pages to scan for keywords
TOP_N_KEYWORDS = 5 # Number of keywords to extract per PDF
# --- End Configuration ---


# --- Category Definitions ---
# Define keywords or patterns for each category. Lowercase for case-insensitive matching.
# Order matters: The first category matched will be used. More specific categories first.
CATEGORY_RULES = {
     "Conference Materials & Presentations": {
        "keywords": {"defcon", "blackhat", "recon", "syscan", "bsides", "hitb", "woot",
                     "offensivecon", "hexacon", "usenix", "derbycon", "firstcon", "conference",
                     "workshop", "presentation", "slides", "talk", "proceedings", "keynote",
                     "training", "seminar", "webinar"},
        "filenames": [r"def con", r"bhus\d{2}", r"bheu\d{2}", r"asia-\d{2}", r"eu-\d{2}",
                      r"us-\d{2}", r"recon \d{4}", r"syscan\d{4}", r"bsides", r"hitb", r"woot",
                      "offensivecon", "hexacon", "usenix", "derbycon", "firstcon", r"slides",
                      r"presentation", r"whitepaper", r"wp\.pdf$", r"_cert(\.pdf)?$", r"_report(\.pdf)?$", r"webinar", r"workshop"]
    },
    "Malware Analysis & Reverse Engineering": {
        "keywords": {"malware", "ransomware", "rootkit", "bootkit", "virus", "spyware", "trojan", "worm",
                     "reverse engineering", "reversing", "disassembly", "disassembler", "decompiler",
                     "ida", "ghidra", "radare2", "x64dbg", "ollydbg", "windbg",
                     "debugging", "obfuscation", "deobfuscation", "packing", "unpacking", "packer",
                     "apt", "advanced persistent threat", "threat intelligence", "threat actor", "ioc", "indicator of compromise",
                     "shellcode", "payload", "botnet", "c2", "command and control", "cybercrime", "malicious",
                     "vx", "vxug", "hollowing", "injection", "injector", "loader", "dropper", "backdoor",
                     "analysis", "static analysis", "dynamic analysis", "behavioral analysis",
                     "signature", "heuristic", "sandbox", "sandboxing", "anti-analysis", "anti-vm",
                     "yara", "sample", "threat", "campaign", "attack chain", "persistence", "stager",
                     "crypter", "polymorphism", "metamorphism"},
        "filenames": [r"malware", r"ransomware", r"rootkit", r"reversing", r"analysis", r"apt\d*"]
    },
    "Exploit Development & Vulnerability Research": {
        "keywords": {"exploit", "exploitation", "exploiting", "exploitability", "vulnerability", "vulnerabilities", "flaw", "weakness", "bug",
                     "pwn", "pwning", "fuzzing", "fuzzer", "afl", "libfuzzer", "bug hunting", "security research",
                     "cve", "common vulnerabilities and exposures", "cvss", "proof-of-concept", "poc", "0day", "zero-day",
                     "rop", "return-oriented programming", "jop", "cop", "gadget", "heap", "heap spray", "heap feng shui",
                     "buffer overflow", "stack overflow", "integer overflow", "use after free", "uaf", "double fetch",
                     "race condition", "mitigation", "mitigations", "bypass", "aslr", "dep", "nx", "cfg", "cfi",
                     "shellcoding", "metasploit", "burp suite", "attack surface", "patch analysis", "patch diffing",
                     "binary exploitation", "web exploitation", "kernel exploitation", "browser exploitation",
                     "vulnerability discovery", "disclosure", "advisory", "security assessment", "penetration test"},
        "filenames": ["pwn2own", r"0x\d{3}-", "_lpe", r"exploit", r"vulnerability", r"fuzzing", r"research"]
    },
     "Cybersecurity Operations & Defense": {
        "keywords": {"red team", "blue team", "purple team", "edr", "endpoint detection", "xdr", "mdr",
                     "antivirus", "av", "anti-malware", "evasion", "defense evasion", "security hardening",
                     "defense", "incident response", "ir", "forensics", "digital forensics", "memory forensics",
                     "penetration testing", "pentest", "pentesting", "cobalt strike", "covenant", "sliver",
                     "c2", "command and control", "lateral movement", "privilege escalation", "post-exploitation",
                     "opsec", "operational security", "phishing", "spear phishing", "social engineering", "lockpicking", "physical security",
                     "osint", "open source intelligence", "sysinternals", "procmon", "autoruns", "wireshark",
                     "adsecurity", "active directory security", "kerberos", "ntlm", "ldap", "group policy",
                     "firewall", "ids", "ips", "intrusion detection", "intrusion prevention", "siem", "log analysis",
                     "detection", "detection engineering", "yara", "sigma", "scanner", "vulnerability scanning",
                     "cybersecurity", "infosec", "information security", "secure", "security", "hardening",
                     "threat hunting", "threat modeling", "risk assessment", "compliance", "audit", "soc",
                     "security operations center", "iam", "identity and access management", "sso", "mfa",
                     "mitre att&ck", "kill chain", "indicators", "ttps", "playbook", "deception"},
         "filenames": ["redsiege", "evilcorp", "operator handbook", "lockbit", r"guide", r"security", r"defense", r"forensic"]
    },
    "Operating System Internals (Windows-Linux)": {
        "keywords": {"kernel", "kernels", "os", "operating system", "windows internals", "linux kernel",
                     "unix", "bsd", "macos internals", "driver", "drivers", "device driver", "kernel module",
                     "bootloader", "boot sequence", "uefi", "bios", "grub", "systemd",
                     "syscalls", "syscall", "system call", "interrupt", "irq", "exception handling",
                     "memory management", "virtual memory", "paging", "segmentation", "memory allocation", "slab", "buddy",
                     "processes", "process management", "threads", "threading", "scheduler", "scheduling", "context switch",
                     "synchronization", "mutex", "semaphore", "spinlock", "deadlock", "concurrency",
                     "file system", "filesystem", "ntfs", "ext4", "btrfs", "zfs", "vfs", "inode",
                     "ipc", "inter-process communication", "pipe", "socket", "shared memory",
                     "x86", "x64", "arm", "arm64", "cpu", "architecture", "registers", "instruction set", "isa",
                     "patchguard", "kpp", "driver signing", "kuser_shared_data", "ntoskrnl", "clfs",
                     "gdi", "win32", "api", "apis", "windows api", "posix", "dll", "dlls", "so", "library",
                     "internals", "architecture", "low level", "ring0", "ring3", "kernel mode", "user mode",
                     "acpi", "hal", "registry", "system architecture", "subsystem", "lsass"},
        "filenames": ["windows internals", "operating system concepts", "linux kernel",
                      "windows-od-srodka", "wdm", "kmdf", "internals", r"kernel", r"driver", r"os"]
    },
    "Debugging & Diagnostics": {
        "keywords": {"debugger", "debuggers", "debugging", "windbg", "gdb", "lldb", "x64dbg", "ollydbg",
                     "crash dump", "memory dump", "core dump", "dump analysis", "post mortem debugging",
                     "tracing", "etw", "dtrace", "strace", "ltrace", "perf", "profiling", "performance analysis",
                     "diagnostics", "troubleshooting", "breakpoint", "watchpoint", "memory inspection",
                     "register view", "stack trace", "symbol", "pdb", "dwarf",
                     "hyperdbg", "dumpanalysis", "reverse debugging", "live debugging", "kernel debugging"},
        "filenames": ["advanced windows debugging", "windbg", "crash dump analysis", r"debugging", r"diagnostics"]
    },
    "Low-Level Programming & Assembly": {
        "keywords": {"assembly", "assembler", "asm", "nasm", "masm", "gas", "registers", "stack", "instruction set", "isa",
                     "opcode", "operand", "addressing mode", "microarchitecture", "cpu pipeline",
                     "hardware interface", "embedded systems programming", "bare metal", "firmware programming",
                     "language programming", "machine code", "linker", "loader", "object file", "abi"},
        "filenames": ["assembly language", "asembler", r"low level programming"]
    },
    "Virtualization & Hypervisors": {
        "keywords": {"virtualization", "hypervisor", "hypervisors", "vmm", "virtual machine monitor",
                     "vmware", "esxi", "workstation", "fusion", "hyper-v", "kvm", "xen", "virtualbox",
                     "qemu", "vm escape", "guest", "host", "sandbox", "sandboxed", "sandboxes",
                     "containerization", "docker", "kubernetes", "lxc", "containerd", "cgroups", "namespaces",
                     "emulation", "emulator", "vmprotect", "themida",
                     "virtual machine", "vm", "vms", "hypercall", "paravirtualization", "vt-x", "amd-v", "ept", "npt",
                     "live migration", "snapshot"},
        "filenames": ["hyper-v", "vmware", r"virtualization", r"sandbox", r"qemu"]
    },
    "Networking & Protocols": {
        "keywords": {"networking", "network", "tcp", "udp", "ip", "ipv4", "ipv6", "icmp", "arp", "ethernet",
                     "socket", "sockets programming", "berkeley sockets", "winsock",
                     "http", "https", "http/2", "http/3", "websocket", "web server", "proxy",
                     "dns", "dhcp", "nat", "vpn", "vpns", "ipsec", "openvpn", "wireguard", "tunneling",
                     "tls", "ssl", "https", "certificates", "pki", "encryption",
                     "protocol", "protocol analysis", "packet capture", "pcap", "wireshark", "tcpdump",
                     "osi model", "routing", "bgp", "ospf", "switching", "vlan", "lan", "wan", "sdn",
                     "cloud networking", "aws", "azure", "gcp", "vpc", "load balancer", "cdn",
                     "network programming", "rpc", "lpc", "alpc", "dcom", "network security",
                     "firewall", "netstat", "ifconfig", "ipconfig", "ping", "traceroute", "netcat", "nmap",
                     "bandwidth", "latency", "qos", "congestion control", "flow control"},
        "filenames": ["cobalt-strike-basics", r"networking", r"protocol", r"tcp", r"http", r"vpn"]
    },
    "Software Development & Programming": {
        "keywords": {"programming", "software development", "coding", "software engineering", "application development",
                     "c", "c++", "python", "rust", "java", "c#", "javascript", "go", "typescript", "perl", "ruby",
                     "algorithms", "data structures", "complexity analysis", "big o notation",
                     "compiler", "compilers", "interpreter", "linker", "build system", "make", "cmake", "msbuild",
                     "sdk", "api", "library", "framework", "ide", "visual studio", "vscode", "jetbrains",
                     "object oriented", "oop", "functional programming", "design patterns", "architecture", "microservices",
                     "multithreading", "concurrency", "parallel programming", "async", "await",
                     "developer", "programmer", "coding", "gui", "ui", "ux", "web development", "backend", "frontend",
                     "database", "sql", "nosql", "testing", "unit testing", "integration testing", "tdd", "bdd",
                     "version control", "git", "svn", "ci/cd", "devops", "agile", "scrum",
                     "directx", "opengl", "vulkan", "graphics programming",
                     "ebpf", "bpf", "programista", "software", "code", "refactoring", "debugging"},
        "filenames": ["programming", "algorithmic thinking", "hands-on rust", "c++", "python", "coding", "software", r"developer", r"compiler"]
    },
    "Cryptography & Steganography": {
        "keywords": {"cryptography", "crypto", "cryptanalysis", "encryption", "decryption", "cipher", "block cipher", "stream cipher",
                     "symmetric", "asymmetric", "public key", "private key", "pki", "certificate", "ca", "x.509",
                     "hashing", "hash function", "sha", "md5", "bcrypt", "scrypt", "hmac", "message authentication",
                     "digital signature", "rsa", "dsa", "ecc", "elliptic curve", "aes", "des", "chacha20",
                     "secure protocols", "tls", "ssl", "ssh", "pgp", "ipsec",
                     "steganography", "steganalysis", "stego", "lsb", "least significant bit", "covert channel", "watermarking",
                     "homomorphic encryption", "zero knowledge proof", "zkp", "quantum cryptography",
                     "openssl", "gnupg", "libgcrypt", "cryptographic library", "random number generation", "rng", "csprng",
                     "kryptograf", "szyfrowan"},
        "filenames": ["cryptography", "steganography", "kryptograficzne", r"encryption", r"crypto"]
    },
    "Hardware & Firmware": {
        "keywords": {"hardware", "firmware", "embedded systems", "microcontroller", "mcu", "microprocessor", "cpu",
                     "intel", "amd", "arm", "risc-v", "soc", "system on chip", "fpga", "asic",
                     "motherboard", "pcb", "circuit board", "schematic", "layout", "datasheet", "errata",
                     "jtag", "swd", "i2c", "spi", "uart", "can bus", "interface", "peripheral", "gpio",
                     "bios", "uefi", "firmware analysis", "firmware modification", "secure boot", "trusted computing", "tpm",
                     "boot process", "bootloader",
                     "memory technology", "ram", "flash", "nand", "eeprom", "dma",
                     "power management", "clock speed", "signal integrity", "electronics", "logic analyzer", "oscilloscope",
                     "npu", "neural processing unit", "gpu", "graphics processing unit"},
        "filenames": ["intel", "firmware", "hardware", r"datasheet", r"arm", r"uefi", r"fpga", r"soc"]
    },
    "Game Development & Hacking": {
        "keywords": {"game development", "gamedev", "game engine", "unity", "unreal engine", "godot", "cryengine",
                     "game programming", "game design", "level design", "graphics programming", "shader", "opengl", "directx", "vulkan",
                     "physics engine", "networking", "multiplayer", "game server", "game client",
                     "game hacking", "cheats", "cheat engine", "aimbot", "wallhack", "esp", "trainer",
                     "anti-cheat", "vac", "battleye", "eac", "reverse engineering game", "memory editing",
                     "game modding", "modding", "assets", "scripting", "lua", "c#"},
        "filenames": ["game hacking", "role-playing games", "directx", r"game", r"cheat", r"unity", r"unreal"]
    },
    "File Formats & Data Structures": {
        "keywords": {"pdf", "pe format", "elf", "macho", "coff", "executable format", "binary format",
                     "parsing", "parser", "serialization", "deserialization", "marshalling",
                     "json", "xml", "yaml", "csv", "protobuf", "flatbuffers", "messagepack",
                     "file format", "data structure", "metadata", "header", "magic number", "file signature",
                     "image format", "jpeg", "png", "gif", "bmp", "audio format", "mp3", "wav", "flac",
                     "video format", "mp4", "mkv", "avi", "archive format", "zip", "tar", "rar", "7z",
                     "document format", "doc", "docx", "odt", "rtf", "specification", "standard", "rfc"},
        "filenames": [r"\[ms-", r".pdf_cmap_fuzzer", r"format", r"specification", r"parser", r"\.pdf$", r"\.docx?$"]
    }
}
# --- End Category Definitions ---


def extract_and_collect_keywords(pdf_dir, kw_model):
    """
    Extracts keywords from PDFs in the specified directory.

    Args:
        pdf_dir (str): The path to the directory containing PDF files.
        kw_model (KeyBERT): The initialized KeyBERT model.

    Returns:
        tuple: A tuple containing:
            - keyword_map (defaultdict): Maps filename to list of lowercase keywords.
            - results_list (list): List of [filename, keyword, score] for CSV/table.
    """
    keyword_map = defaultdict(list)
    results_list = []
    abs_pdf_dir = os.path.abspath(pdf_dir)
    print(f"Scanning PDF directory: {abs_pdf_dir}")
    print("-" * 30)

    pdf_files = [f for f in os.listdir(abs_pdf_dir) if f.lower().endswith(".pdf") and os.path.isfile(os.path.join(abs_pdf_dir, f))]
    total_files = len(pdf_files)
    start_time = time.time()

    for i, filename in enumerate(pdf_files):
        file_path = os.path.join(abs_pdf_dir, filename)
        print(f"Processing ({i+1}/{total_files}): {filename}")
        text = ""
        try:
            # Extract text from first few pages
            doc = pymupdf.open(file_path)
            num_pages_to_scan = min(PAGES_TO_SCAN, len(doc))
            for page_num in range(num_pages_to_scan):
                 page = doc.load_page(page_num) # Use load_page for better control
                 text += page.get_text("text") # Extract plain text
            doc.close()

            if not text.strip():
                print("  Warning: No text extracted or empty text.")
                continue # Skip if no text extracted

            # Extract keywords
            # Consider adding parameters like keyphrase_ngram_range, stop_words='english' if needed
            keywords = kw_model.extract_keywords(text, top_n=TOP_N_KEYWORDS)

            if not keywords:
                print("  Warning: KeyBERT returned no keywords.")

            # Store results
            for keyword, score in keywords:
                clean_keyword = keyword.lower()
                results_list.append([filename, keyword, round(score, 2)])
                keyword_map[filename].append(clean_keyword) # Store lowercase keyword for matching

        except pymupdf.errors.FileDataError:
             print(f"  Error: Could not open or read (possibly encrypted or corrupted) - {filename}")
        except Exception as e:
            print(f"  Error processing {filename}: {e}")

    end_time = time.time()
    print("-" * 30)
    print(f"Keyword extraction finished in {end_time - start_time:.2f} seconds.")
    return keyword_map, results_list


def display_keyword_table(results_list):
    """Displays the extracted keywords in a formatted table."""
    if results_list:
        print("\n--- Extracted Keywords Summary ---")
        # Sort results by filename, then score (desc) for better readability
        results_list.sort(key=lambda x: (x[0], -x[2]))
        print(tabulate(results_list, headers=["Filename", "Keyword", "Observability (Score)"], tablefmt="fancy_grid"))
        print("-" * 30)
    else:
        print("\nNo keywords were extracted to display.")


def write_keywords_to_csv(results_list, output_csv):
    """Saves the extracted keywords to a CSV file."""
    if not results_list:
        print("\nNo keyword data to write to CSV.")
        return

    try:
        # Sort results by filename, then score (desc) before writing
        results_list.sort(key=lambda x: (x[0], -x[2]))
        with open(output_csv, mode="w", newline='', encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow(["Filename", "Keyword", "Observability (Score)"])  # CSV header
            writer.writerows(results_list)
        print(f"\n✅ Keyword results saved to {output_csv}")
    except Exception as e:
        print(f"\n❌ Error writing keywords to CSV {output_csv}: {e}")


def get_category(filename, keywords_for_file):
    """Determines the category based on keywords and filename patterns."""
    filename_lower = filename.lower()
    keywords_set = set(keywords_for_file) # Use set for efficient lookup

    for category, rules in CATEGORY_RULES.items():
        # Check keywords first (often more indicative)
        if rules.get("keywords") and not keywords_set.isdisjoint(rules["keywords"]):
            # print(f"  Debug: Matched category '{category}' based on keywords: {keywords_set.intersection(rules['keywords'])}")
            return category

        # Check filename patterns (regex)
        for pattern in rules.get("filenames", []):
            try:
                # Use re.IGNORECASE for case-insensitive filename matching
                if re.search(pattern, filename_lower, re.IGNORECASE):
                    # print(f"  Debug: Matched category '{category}' based on filename pattern: '{pattern}'")
                    return category
            except re.error as e:
                print(f"  Warning: Invalid regex pattern '{pattern}' for category '{category}': {e}")

    # print(f"  Debug: No specific category matched for '{filename}'.")
    return DEFAULT_CATEGORY


def categorize_and_copy_files(pdf_dir, keyword_map):
    """Categorizes and copies PDF files based on keywords and rules."""
    print("\n--- Starting Categorization and Copying ---")
    categorized_count = 0
    uncategorized_count = 0
    skipped_count = 0
    error_count = 0

    abs_pdf_dir = os.path.abspath(pdf_dir)

    # Iterate through files *known* to have keywords first
    files_to_process = list(keyword_map.keys())
    # Add files that might not have keywords extracted (e.g., errors during extraction)
    for item in os.listdir(abs_pdf_dir):
         if item.lower().endswith(".pdf") and os.path.isfile(os.path.join(abs_pdf_dir, item)) and item not in files_to_process:
              files_to_process.append(item)

    total_files = len(files_to_process)

    for i, filename in enumerate(files_to_process):
        source_path = os.path.join(abs_pdf_dir, filename)

        print(f"Categorizing ({i+1}/{total_files}): {filename}")

        # Get keywords (might be empty if extraction failed)
        file_keywords = keyword_map.get(filename, [])

        # Determine category
        category = get_category(filename, file_keywords)
        print(f"  Category: {category}")

        # Create category directory if it doesn't exist (within the source dir)
        category_dir = os.path.join(abs_pdf_dir, category)
        try:
            os.makedirs(category_dir, exist_ok=True)
        except OSError as e:
            print(f"  Error creating directory '{category_dir}': {e}. Skipping file.")
            error_count += 1
            continue # Skip to the next file

        # Define destination path
        destination_path = os.path.join(category_dir, filename)

        # Copy the file if it doesn't exist in destination
        if not os.path.exists(destination_path):
            try:
                shutil.copy2(source_path, destination_path)
                print(f"  Copied to: {category_dir}")
                if category == DEFAULT_CATEGORY:
                    uncategorized_count += 1
                else:
                    categorized_count += 1
            except Exception as e:
                print(f"  Error copying '{filename}' to '{category_dir}': {e}")
                error_count += 1
        else:
            print(f"  Skipped: File already exists in '{category_dir}'")
            skipped_count += 1

    print("\n--- Categorization Summary ---")
    print(f"Successfully categorized and copied: {categorized_count} files")
    print(f"Placed in '{DEFAULT_CATEGORY}': {uncategorized_count} files")
    print(f"Skipped (already exists): {skipped_count} files")
    print(f"Errors during copying/folder creation: {error_count} files")
    print("-----------------------------")


def main():
    """Main function to run the PDF sort."""
    if not os.path.isdir(PDF_SOURCE_DIR):
        print(f"Error: PDF source directory not found or is not a directory: {PDF_SOURCE_DIR}")
        return

    print("Initializing KeyBERT model...")
    try:
        kw_model = KeyBERT()
    except Exception as e:
        print(f"Error initializing KeyBERT model: {e}")
        print("Please ensure you have installed KeyBERT and its dependencies (e.g., sentence-transformers, torch).")
        return
    print("KeyBERT model initialized.")

    # 1. Extract Keywords and build keyword map
    keyword_map, results_list = extract_and_collect_keywords(PDF_SOURCE_DIR, kw_model)

    # 2. Display table
    display_keyword_table(results_list)

    # 3. Save keywords to CSV
    write_keywords_to_csv(results_list, OUTPUT_CSV)

    # 4. Categorize and copy files using the generated keyword_map
    categorize_and_copy_files(PDF_SOURCE_DIR, keyword_map)

    print("\nPDF Sorting finished.")

if __name__ == "__main__":
    main()
