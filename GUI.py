import tkinter as tk
from tkinter import messagebox
import json

# Categories and their respective methods
categories = {
    "Website": [
        "Check robots.txt",
        "Look for hidden parameters",
        "Try SQL Injection",
        "Test for XSS",
        "Check for Open Redirects",
        "Scan with Nikto",
        "Use Burp Suite for fuzzing",
        "Look for subdomains",
        "Try directory brute-forcing (gobuster, dirb)",
        "Analyze JavaScript for hidden endpoints",
        "Check for weak authentication mechanisms",
        "Inspect CSP headers for misconfigurations",
        "JWT manipulation",
        "WAF bypass techniques",
        "GraphQL abuse",
        "SSRF detection",
        "XXE attacks",
        "Server-side template injection (SSTI)",
        "Prototype pollution vulnerabilities"
    ],
    "Log & Forensics": [
        "Analyze timestamps",
        "Search for anomalies",
        "Extract metadata",
        "Look for credential leaks",
        "Check for hidden fields",
        "Analyze failed login attempts",
        "Correlate logs with known attacks",
        "Look for unexpected IP addresses",
        "Check for encoded or obfuscated data",
        "Compare logs across multiple sources",
        "Identify brute-force attempts",
        "Search for indicators of compromise (IoCs)",
        "Regex-based log searching",
        "SIEM-style correlation",
        "Memory dump analysis (Volatility)",
        "DFIR timeline reconstruction",
        "Disk image forensics"
    ],
    "Cryptography": [
        "Break weak RSA (e.g., common primes)",
        "Padding oracle attacks",
        "Elliptic curve cryptanalysis",
        "Identify improper key storage",
        "Decrypt AES modes with flaws",
        "Analyze digital signatures for weaknesses",
        "Lattice-based attacks (Coppersmith)",
        "DSA vulnerabilities",
        "Blockchain forensics"
    ],
    "Steganography": [
        "Use steghide",
        "Check LSB",
        "Analyze metadata",
        "Use zsteg for PNG files",
        "Try binwalk for hidden files",
        "Look for hidden messages in color channels",
        "Extract potential encoded text",
        "Use exiftool for metadata analysis",
        "Check for appended data beyond EOF",
        "Try different image formats (JPEG, BMP, WAV, etc.)",
        "Analyze frequency domain for hidden signals",
        "Audio steganography",
        "GIF artifacts",
        "F5 JPEG analysis",
        "Video-based steganography",
        "Outguess & OpenPuff analysis"
    ],
    "Binary Exploitation": [
        "Identify buffer overflows",
        "Analyze format string vulnerabilities",
        "Use ret2libc for exploitation",
        "ROP chain construction",
        "Heap overflow detection",
        "Shellcode injection",
        "Debug with GDB and Pwntools",
        "Kernel exploitation",
        "Use-after-free (UAF) attacks",
        "Format string abuses"
    ],
    "Malware Analysis": [
        "Check VirusTotal",
        "Analyze with Ghidra",
        "Run in sandbox",
        "Use YARA rules",
        "Inspect with strings command",
        "Look for obfuscated code",
        "Analyze dynamic behavior",
        "Check persistence mechanisms (registry, startup scripts)",
        "Look for encoded payloads",
        "Reverse shell detection",
        "Extract embedded configurations",
        "Analyze process execution flow",
        "Sysmon event tracking",
        "PE header analysis",
        "PowerShell deobfuscation",
        "Malicious macro analysis",
        "Ransomware behavior tracking",
        "Automated malware sandboxing"
    ],
    "Privilege Escalation": [
        "Check for SUID binaries",
        "Kernel vulnerability exploitation",
        "Misconfigured services",
        "Weak sudo configurations",
        "Cron job manipulation",
        "Abusing writable paths",
        "Escalating from Docker to root",
        "Active Directory privilege escalation",
        "Token impersonation",
        "Group policy hijacking"
    ],
    "Traffic Analysis": [
        "Analyze HTTP headers",
        "Look for cookies",
        "Check GET/POST requests",
        "Look for API keys in responses",
        "Use Wireshark to inspect traffic",
        "Analyze request-response patterns",
        "Identify unusual user agents",
        "Search for encoded data in requests",
        "Look for WebSocket traffic",
        "Test replay attacks on captured requests",
        "Check DNS requests for data exfiltration",
        "Inspect TLS/SSL versions and cipher suites",
        "MITM attack simulation",
        "Protocol-specific filters",
        "Decrypt encrypted traffic",
        "Analyze HTTP/2 & QUIC protocols",
        "Detect covert channels"
    ]
}

# Load saved progress
try:
    with open("progress.json", "r") as f:
        progress = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    progress = {cat: [False] * len(categories[cat]) for cat in categories}

def validate_progress():
    for cat in categories:
        if cat not in progress or len(progress[cat]) != len(categories[cat]):
            progress[cat] = [False] * len(categories[cat])
    save_progress()

def save_progress():
    with open("progress.json", "w") as f:
        json.dump(progress, f)

validate_progress()

# GUI Setup
root = tk.Tk()
root.title("CTF Support Tool")
root.configure(bg="black")

def open_category(category):
    window = tk.Toplevel(root, bg="black")
    window.title(category)
    
    check_vars = [tk.BooleanVar(value=progress[category][i]) for i in range(len(categories[category]))]
    
    def update_progress():
        for i in range(len(categories[category])):
            progress[category][i] = check_vars[i].get()
        save_progress()
    
    for i, method in enumerate(categories[category]):
        tk.Checkbutton(window, text=method, variable=check_vars[i], command=update_progress, bg="black", fg="white", selectcolor="black", activebackground="black", activeforeground="white", highlightthickness=0).pack(anchor="w")
    
    tk.Button(window, text="Suggest Next Steps", command=lambda: messagebox.showinfo("Next Steps", "Try these next: " + ', '.join([categories[category][i] for i, checked in enumerate(check_vars) if not checked.get()]) if any(not checked.get() for checked in check_vars) else "You've tried everything! Consider re-evaluating clues."), bg="black", fg="white").pack(pady=5)

for category in categories.keys():
    tk.Button(root, text=category, width=30, command=lambda c=category: open_category(c), bg="black", fg="white").pack(pady=5)

tk.Button(root, text="Exit", command=root.quit, bg="black", fg="white").pack(pady=10)
root.mainloop()
