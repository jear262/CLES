#!/bin/bash

#==============================================================================
# Comprehensive Linux System Enumeration Script
# Version: 1.0 Ultimate Edition
# Purpose: Complete enumeration for security assessments and privilege escalation
#==============================================================================

# Default output settings
OUTPUT_TEXT=false
OUTPUT_HTML=false
OUTPUT_DIR="./enum_results"
OUTPUT_PREFIX="linux_enum"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
QUIET_MODE=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--text)
            OUTPUT_TEXT=true
            shift
            ;;
        -h|--html)
            OUTPUT_HTML=true
            shift
            ;;
        -a|--all)
            OUTPUT_TEXT=true
            OUTPUT_HTML=true
            shift
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -q|--quiet)
            QUIET_MODE=true
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  -t, --text          Generate text report"
            echo "  -h, --html          Generate HTML report"
            echo "  -a, --all           Generate all report formats"
            echo "  -o, --output DIR    Output directory (default: ./enum_results)"
            echo "  -q, --quiet         Suppress terminal output (only write to files)"
            echo "  --help              Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                          # Run with terminal output only"
            echo "  $0 -t                       # Run and save text report"
            echo "  $0 -a -o /tmp/reports       # Generate all reports in /tmp/reports"
            echo "  $0 -t -q                    # Silent mode with text report"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Create output directory if needed
if [ "$OUTPUT_TEXT" = true ] || [ "$OUTPUT_HTML" = true ]; then
    mkdir -p "$OUTPUT_DIR"
    if [ $? -ne 0 ]; then
        echo "Error: Cannot create output directory: $OUTPUT_DIR"
        exit 1
    fi
fi

# Setup output files
TEXT_OUTPUT="$OUTPUT_DIR/${OUTPUT_PREFIX}_${TIMESTAMP}.txt"
HTML_OUTPUT="$OUTPUT_DIR/${OUTPUT_PREFIX}_${TIMESTAMP}.html"

# Function to handle output
output() {
    if [ "$QUIET_MODE" = false ]; then
        echo -e "$1"
    fi
    if [ "$OUTPUT_TEXT" = true ]; then
        echo -e "$1" | sed 's/\x1b\[[0-9;]*m//g' >> "$TEXT_OUTPUT"
    fi
}

# Function to add to HTML report
html_append() {
    if [ "$OUTPUT_HTML" = true ]; then
        echo "$1" >> "$HTML_OUTPUT"
    fi
}

# Initialize HTML report
if [ "$OUTPUT_HTML" = true ]; then
    cat > "$HTML_OUTPUT" << 'HTMLHEAD'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Linux Enumeration Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        .metadata {
            background: #f8f9fa;
            padding: 20px 40px;
            border-bottom: 2px solid #e9ecef;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
        }
        .metadata-item {
            display: flex;
            align-items: center;
        }
        .metadata-label {
            font-weight: bold;
            color: #667eea;
            margin-right: 10px;
        }
        .content {
            padding: 40px;
        }
        .section {
            margin-bottom: 40px;
            border-left: 4px solid #667eea;
            padding-left: 20px;
        }
        .section-title {
            font-size: 1.8em;
            color: #667eea;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #e9ecef;
        }
        .subsection {
            margin-bottom: 25px;
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
        }
        .subsection-title {
            font-size: 1.3em;
            color: #495057;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
        }
        .subsection-title::before {
            content: "▸";
            margin-right: 10px;
            color: #667eea;
            font-weight: bold;
        }
        .info-block {
            background: white;
            padding: 15px;
            border-radius: 5px;
            margin-top: 10px;
            border-left: 3px solid #17a2b8;
        }
        .warning-block {
            background: #fff3cd;
            padding: 15px;
            border-radius: 5px;
            margin-top: 10px;
            border-left: 3px solid #ffc107;
        }
        .critical-block {
            background: #f8d7da;
            padding: 15px;
            border-radius: 5px;
            margin-top: 10px;
            border-left: 3px solid #dc3545;
        }
        .success-block {
            background: #d4edda;
            padding: 15px;
            border-radius: 5px;
            margin-top: 10px;
            border-left: 3px solid #28a745;
        }
        .code-block {
            background: #2d2d2d;
            color: #f8f8f2;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            margin-top: 10px;
        }
        .badge {
            display: inline-block;
            padding: 5px 10px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: bold;
            margin-right: 5px;
        }
        .badge-critical { background: #dc3545; color: white; }
        .badge-high { background: #fd7e14; color: white; }
        .badge-warning { background: #ffc107; color: #333; }
        .badge-info { background: #17a2b8; color: white; }
        .badge-success { background: #28a745; color: white; }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }
        .stat-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .stat-number {
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }
        .stat-label {
            font-size: 0.9em;
            opacity: 0.9;
        }
        .toc {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 30px;
        }
        .toc-title {
            font-size: 1.5em;
            margin-bottom: 15px;
            color: #667eea;
        }
        .toc-item {
            padding: 8px 0;
            border-bottom: 1px solid #e9ecef;
        }
        .toc-item:last-child {
            border-bottom: none;
        }
        .toc-item a {
            color: #495057;
            text-decoration: none;
            transition: color 0.3s;
        }
        .toc-item a:hover {
            color: #667eea;
        }
        .footer {
            background: #2d3436;
            color: white;
            padding: 30px;
            text-align: center;
        }
        pre {
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e9ecef;
        }
        th {
            background: #667eea;
            color: white;
            font-weight: bold;
        }
        tr:hover {
            background: #f8f9fa;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Linux System Enumeration Report</h1>
            <p>Comprehensive Security Assessment</p>
        </div>
HTMLHEAD
    
    # Add metadata
    html_append "        <div class=\"metadata\">"
    html_append "            <div class=\"metadata-item\"><span class=\"metadata-label\">📅 Date:</span> $(date)</div>"
    html_append "            <div class=\"metadata-item\"><span class=\"metadata-label\">🖥️ Hostname:</span> $(hostname)</div>"
    html_append "            <div class=\"metadata-item\"><span class=\"metadata-label\">👤 User:</span> $(whoami)</div>"
    html_append "            <div class=\"metadata-item\"><span class=\"metadata-label\">🐧 Kernel:</span> $(uname -r)</div>"
    html_append "        </div>"
    html_append "        <div class=\"content\">"
fi

# Color definitions
C=$(printf '\033')
RED="${C}[1;31m"
GREEN="${C}[1;32m"
YELLOW="${C}[1;33m"
BLUE="${C}[1;34m"
MAGENTA="${C}[1;35m"
CYAN="${C}[1;36m"
WHITE="${C}[1;37m"
GRAY="${C}[1;90m"
NC="${C}[0m"
BOLD="${C}[1m"
UNDERLINE="${C}[4m"
ITALIC="${C}[3m"

# Box drawing characters
HEADER_CHAR="="
SECTION_CHAR="-"

#==============================================================================
# Helper Functions
#==============================================================================

# Print a fancy header
print_header() {
    local text="$1"
    local width=80
    output ""
    output "${CYAN}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${NC}"
    output "${BOLD}${WHITE}  $text${NC}"
    output "${CYAN}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${HEADER_CHAR}${NC}"
    
    # HTML section header
    local section_id=$(echo "$text" | tr '[:upper:]' '[:lower:]' | tr ' ' '-')
    html_append "            <div class=\"section\" id=\"$section_id\">"
    html_append "                <h2 class=\"section-title\">$text</h2>"
}

# Print a section title
print_section() {
    local text="$1"
    output ""
    output "${YELLOW}┌─[ ${BOLD}$text${NC}${YELLOW} ]${NC}"
    
    # HTML subsection
    html_append "                <div class=\"subsection\">"
    html_append "                    <h3 class=\"subsection-title\">$text</h3>"
}

# Print section separator
print_separator() {
    output "${GRAY}└─────────────────────────────────────────────────────────────────────────────${NC}"
    html_append "                </div>"
}

# Print info line
print_info() {
    output "${BLUE}[*]${NC} $1"
    html_append "                    <div class=\"info-block\">ℹ️ $1</div>"
}

# Print success line
print_success() {
    output "${GREEN}[✓]${NC} $1"
    html_append "                    <div class=\"success-block\">✓ $1</div>"
}

# Print warning line
print_warning() {
    output "${YELLOW}[!]${NC} $1"
    html_append "                    <div class=\"warning-block\">⚠️ $1</div>"
}

# Print error line
print_error() {
    output "${RED}[✗]${NC} $1"
    html_append "                    <div class=\"warning-block\">✗ $1</div>"
}

# Print critical finding
print_critical() {
    output "${RED}${BOLD}[!!!]${NC} $1"
    html_append "                    <div class=\"critical-block\">🚨 <strong>$1</strong></div>"
}

# Print code block
print_code() {
    output "$1"
    local clean_text=$(echo "$1" | sed 's/\x1b\[[0-9;]*m//g')
    html_append "                    <pre class=\"code-block\">$clean_text</pre>"
}

#==============================================================================
# Banner
#==============================================================================

if [ "$QUIET_MODE" = false ]; then
    clear
fi

output "${CYAN}"
output '╔═══════════════════════════════════════════════════════════════════════════╗'
output '║                                                                           ║'
output '║           ██╗     ██╗███╗   ██╗██╗   ██╗██╗  ██╗                        ║'
output '║           ██║     ██║████╗  ██║██║   ██║╚██╗██╔╝                        ║'
output '║           ██║     ██║██╔██╗ ██║██║   ██║ ╚███╔╝                         ║'
output '║           ██║     ██║██║╚██╗██║██║   ██║ ██╔██╗                         ║'
output '║           ███████╗██║██║ ╚████║╚██████╔╝██╔╝ ██╗                        ║'
output '║           ╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝                        ║'
output '║                                                                           ║'
output '║              COMPREHENSIVE ENUMERATION TOOL v1.0                         ║'
output '║                                                                           ║'
output '╚═══════════════════════════════════════════════════════════════════════════╝'
output "${NC}"

output "${RED}${BOLD}⚠ WARNING ⚠${NC}"
output "${YELLOW}This script is for authorized security assessments only.${NC}"
output "${YELLOW}Only use on systems you own or have explicit permission to test.${NC}"
output ""
output "${GRAY}Started: $(date)${NC}"
output "${GRAY}Hostname: $(hostname)${NC}"
output "${GRAY}Current User: $(whoami)${NC}"

if [ "$OUTPUT_TEXT" = true ]; then
    output "${GRAY}Text Output: $TEXT_OUTPUT${NC}"
fi
if [ "$OUTPUT_HTML" = true ]; then
    output "${GRAY}HTML Output: $HTML_OUTPUT${NC}"
fi

output ""
sleep 1

#==============================================================================
# System Information
#==============================================================================

print_header "SYSTEM INFORMATION"

# Operating System
print_section "Operating System Details"
if [ -f /etc/os-release ]; then
    print_success "Found /etc/os-release"
    cat /etc/os-release 2>/dev/null | sed "s/^/  ${GRAY}│${NC} /"
else
    print_info "Checking alternative sources..."
fi

echo ""
print_info "Kernel Information:"
uname -a 2>/dev/null | sed "s/^/  ${GRAY}│${NC} /"

if command -v lsb_release &> /dev/null; then
    echo ""
    print_info "LSB Information:"
    lsb_release -a 2>/dev/null | sed "s/^/  ${GRAY}│${NC} /"
fi

echo ""
print_info "Kernel version: ${BOLD}$kernel_version${NC}"
print_separator

# Kernel Vulnerability Check
print_section "Kernel Vulnerability Analysis"
kernel_version=$(uname -r)
kernel_major=$(echo $kernel_version | cut -d. -f1)
kernel_minor=$(echo $kernel_version | cut -d. -f2)
kernel_patch=$(echo $kernel_version | cut -d. -f3 | cut -d- -f1)

print_info "Detected Kernel: ${BOLD}$kernel_version${NC}"
print_info "Parsed Version: ${BOLD}$kernel_major.$kernel_minor.$kernel_patch${NC}"
echo ""
print_warning "Checking against known vulnerable kernel versions..."
echo ""

# Function to compare versions
version_lte() {
    [ "$1" = "$2" ] && return 0
    [ "$1" = "$(echo -e "$1\n$2" | sort -V | head -n1)" ]
}

version_in_range() {
    local current=$1
    local min_ver=$2
    local max_ver=$3
    version_lte "$min_ver" "$current" && version_lte "$current" "$max_ver"
}

vulnerable_found=0

# CVE-2022-0847 - Dirty Pipe
if version_in_range "$kernel_major.$kernel_minor.$kernel_patch" "5.8.0" "5.16.10"; then
    print_critical "CVE-2022-0847 (Dirty Pipe) - Arbitrary file overwrite"
    echo -e "  ${GRAY}│${NC} ${RED}Severity: CRITICAL${NC}"
    echo -e "  ${GRAY}│${NC} Affected: Linux 5.8 - 5.16.10"
    echo -e "  ${GRAY}│${NC} Exploit: https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits"
    echo ""
    ((vulnerable_found++))
fi

# CVE-2021-4034 - PwnKit (Polkit)
print_info "CVE-2021-4034 (PwnKit/Polkit) - Check polkit version separately"
echo -e "  ${GRAY}│${NC} ${YELLOW}Affects all versions since 2009${NC}"
echo -e "  ${GRAY}│${NC} Run: pkexec --version"
echo -e "  ${GRAY}│${NC} Vulnerable if polkit < 0.120-1"
echo -e "  ${GRAY}│${NC} Exploit: https://github.com/arthepsy/CVE-2021-4034"
echo ""

# CVE-2021-3493 - OverlayFS
if version_in_range "$kernel_major.$kernel_minor.$kernel_patch" "4.4.0" "5.11.0"; then
    print_critical "CVE-2021-3493 (OverlayFS) - Local privilege escalation"
    echo -e "  ${GRAY}│${NC} ${RED}Severity: HIGH${NC}"
    echo -e "  ${GRAY}│${NC} Affected: Linux 4.4 - 5.11"
    echo -e "  ${GRAY}│${NC} Exploit: https://github.com/briskets/CVE-2021-3493"
    echo ""
    ((vulnerable_found++))
fi

# CVE-2021-3156 - Sudo Baron Samedit
print_info "CVE-2021-3156 (Sudo Baron Samedit) - Check sudo version"
echo -e "  ${GRAY}│${NC} Run: sudo --version"
echo -e "  ${GRAY}│${NC} Vulnerable: sudo 1.8.2 - 1.8.31p2, 1.9.0 - 1.9.5p1"
echo -e "  ${GRAY}│${NC} Exploit: https://github.com/blasty/CVE-2021-3156"
echo ""

# CVE-2017-16995 - eBPF
if version_in_range "$kernel_major.$kernel_minor.$kernel_patch" "4.4.0" "4.14.11"; then
    print_critical "CVE-2017-16995 (eBPF) - Local privilege escalation"
    echo -e "  ${GRAY}│${NC} ${RED}Severity: HIGH${NC}"
    echo -e "  ${GRAY}│${NC} Affected: Linux 4.4 - 4.14.11"
    echo -e "  ${GRAY}│${NC} Exploit: https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/43434.zip"
    echo ""
    ((vulnerable_found++))
fi

# CVE-2016-5195 - Dirty COW
if version_lte "$kernel_major.$kernel_minor.$kernel_patch" "4.8.3"; then
    print_critical "CVE-2016-5195 (Dirty COW) - Race condition in memory subsystem"
    echo -e "  ${GRAY}│${NC} ${RED}Severity: CRITICAL${NC}"
    echo -e "  ${GRAY}│${NC} Affected: Linux 2.6.22 - 4.8.3"
    echo -e "  ${GRAY}│${NC} Exploit: https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs"
    echo ""
    ((vulnerable_found++))
fi

# CVE-2016-0728 - Keyring
if version_in_range "$kernel_major.$kernel_minor.$kernel_patch" "3.8.0" "4.4.1"; then
    print_critical "CVE-2016-0728 (Keyring) - Use-after-free"
    echo -e "  ${GRAY}│${NC} ${RED}Severity: HIGH${NC}"
    echo -e "  ${GRAY}│${NC} Affected: Linux 3.8 - 4.4.1"
    echo -e "  ${GRAY}│${NC} Exploit: https://www.exploit-db.com/exploits/39277"
    echo ""
    ((vulnerable_found++))
fi

# CVE-2015-1328 - OverlayFS (Ubuntu)
if version_in_range "$kernel_major.$kernel_minor.$kernel_patch" "3.13.0" "3.19.0"; then
    if grep -qi "ubuntu" /etc/os-release 2>/dev/null; then
        print_critical "CVE-2015-1328 (OverlayFS Ubuntu) - Local privilege escalation"
        echo -e "  ${GRAY}│${NC} ${RED}Severity: HIGH${NC}"
        echo -e "  ${GRAY}│${NC} Affected: Ubuntu kernels 3.13.0 - 3.19.0"
        echo -e "  ${GRAY}│${NC} Exploit: https://www.exploit-db.com/exploits/37292"
        echo ""
        ((vulnerable_found++))
    fi
fi

# CVE-2014-4699 - ptrace/sysret
if version_lte "$kernel_major.$kernel_minor.$kernel_patch" "3.15.4"; then
    print_critical "CVE-2014-4699 (ptrace/sysret) - Local privilege escalation"
    echo -e "  ${GRAY}│${NC} ${RED}Severity: HIGH${NC}"
    echo -e "  ${GRAY}│${NC} Affected: Linux 2.6.32 - 3.15.4"
    echo -e "  ${GRAY}│${NC} Exploit: https://www.exploit-db.com/exploits/34134"
    echo ""
    ((vulnerable_found++))
fi

# CVE-2010-3904 - RDS Protocol
if version_lte "$kernel_major.$kernel_minor.$kernel_patch" "2.6.36"; then
    print_critical "CVE-2010-3904 (RDS Protocol) - Local privilege escalation"
    echo -e "  ${GRAY}│${NC} ${RED}Severity: HIGH${NC}"
    echo -e "  ${GRAY}│${NC} Affected: Linux 2.6.30 - 2.6.36"
    echo -e "  ${GRAY}│${NC} Exploit: https://www.exploit-db.com/exploits/15285"
    echo ""
    ((vulnerable_found++))
fi

# CVE-2009-2698 - udp_sendmsg
if version_lte "$kernel_major.$kernel_minor.$kernel_patch" "2.6.31"; then
    print_critical "CVE-2009-2698 (udp_sendmsg) - NULL pointer dereference"
    echo -e "  ${GRAY}│${NC} ${RED}Severity: HIGH${NC}"
    echo -e "  ${GRAY}│${NC} Affected: Linux 2.6.0 - 2.6.31"
    echo -e "  ${GRAY}│${NC} Exploit: https://www.exploit-db.com/exploits/9575"
    echo ""
    ((vulnerable_found++))
fi

# Additional recent CVEs based on version ranges
if version_in_range "$kernel_major.$kernel_minor.$kernel_patch" "5.10.0" "5.15.0"; then
    print_warning "CVE-2022-2586 (nf_tables) - Use-after-free"
    echo -e "  ${GRAY}│${NC} Affected: Linux 5.10 - 5.15"
    echo -e "  ${GRAY}│${NC} Check patch level for exact vulnerability"
    echo ""
fi

if version_in_range "$kernel_major.$kernel_minor.$kernel_patch" "4.15.0" "5.10.0"; then
    print_warning "CVE-2022-34918 (Netfilter) - Buffer overflow"
    echo -e "  ${GRAY}│${NC} Affected: Linux 4.15 - 5.10"
    echo -e "  ${GRAY}│${NC} Exploit may be available"
    echo ""
fi

# Summary
echo ""
if [ $vulnerable_found -gt 0 ]; then
    print_critical "Found ${BOLD}$vulnerable_found${NC} ${RED}confirmed kernel vulnerabilities!${NC}"
    echo -e "  ${GRAY}│${NC} Test exploits in controlled environment"
    echo -e "  ${GRAY}│${NC} Verify exploit compatibility before use"
else
    print_success "No critical kernel vulnerabilities detected in this version"
    print_info "However, always check for latest CVEs and patches"
fi

echo ""
print_info "Additional Resources:"
echo -e "  ${GRAY}│${NC} https://www.linuxkernelcves.com/kernel/$kernel_major.$kernel_minor.$kernel_patch"
echo -e "  ${GRAY}│${NC} https://github.com/nomi-sec/PoC-in-GitHub"
echo -e "  ${GRAY}│${NC} https://github.com/BColes/kernel-exploits"
echo -e "  ${GRAY}│${NC} https://www.exploit-db.com/"

print_separator

# Hostname
print_section "Hostname Information"
print_info "Hostname: ${BOLD}$(hostname)${NC}"
print_info "FQDN: ${BOLD}$(hostname -f 2>/dev/null || echo "N/A")${NC}"
print_info "Domain: ${BOLD}$(dnsdomainname 2>/dev/null || echo "N/A")${NC}"
print_separator

# System Uptime
print_section "System Uptime and Load"
uptime | sed "s/^/  ${GRAY}│${NC} /"
print_separator

# VM Detection
print_section "Virtualization Detection"
if command -v systemd-detect-virt &> /dev/null; then
    virt_type=$(systemd-detect-virt)
    if [ "$virt_type" != "none" ]; then
        print_warning "Running in virtual environment: ${BOLD}$virt_type${NC}"
    else
        print_info "No virtualization detected"
    fi
else
    print_info "Checking dmidecode..."
    if [ -r /sys/class/dmi/id/product_name ]; then
        product_name=$(cat /sys/class/dmi/id/product_name 2>/dev/null)
        print_info "Product: $product_name"
    fi
fi
print_separator

#==============================================================================
# User and Group Information
#==============================================================================

print_header "USER & GROUP INFORMATION"

# Current User
print_section "Current User Context"
print_info "User Information:"
id 2>/dev/null | sed "s/^/  ${GRAY}│${NC} /"
echo ""
print_info "Active User: ${BOLD}$(whoami)${NC}"
print_info "User Groups: ${BOLD}$(groups)${NC}"
print_info "User ID: ${BOLD}$(id -u)${NC}"
print_info "Group ID: ${BOLD}$(id -g)${NC}"

# Check for interesting groups
if groups | grep -qE "(sudo|wheel|admin|root|docker|lxd|disk|video)"; then
    print_critical "User is in privileged groups!"
    groups | sed "s/^/  ${GRAY}│${NC} /"
fi
print_separator

# Super Users
print_section "Privileged Users (UID 0)"
super_users=$(awk -F: '($3 == "0") {print $1}' /etc/passwd 2>/dev/null)
if [ -n "$super_users" ]; then
    echo "$super_users" | while read user; do
        print_warning "Root user found: ${BOLD}$user${NC}"
    done
else
    print_info "No additional root users found"
fi
print_separator

# System Users
print_section "System User Accounts"
print_info "Total users: ${BOLD}$(wc -l < /etc/passwd)${NC}"
echo ""
print_info "Users with login shells:"
grep -vE '(nologin|false)$' /etc/passwd | cut -d: -f1 | sed "s/^/  ${GRAY}│${NC} /"
print_separator

# Home Directories
print_section "Home Directories"
print_info "Accessible home directories:"
for home_dir in /home/*; do
    if [ -d "$home_dir" ] && [ -r "$home_dir" ]; then
        print_warning "Can read: ${BOLD}$home_dir${NC}"
        ls -la "$home_dir" 2>/dev/null | head -n 10 | sed "s/^/    ${GRAY}│${NC} /"
    fi
done
print_separator

# Shadow File Access
print_section "Password Shadow File Test"
if [ -r /etc/shadow ]; then
    print_critical "Shadow file is readable! This is a security risk."
    shadow_count=$(wc -l < /etc/shadow 2>/dev/null)
    print_info "Entries found: ${BOLD}$shadow_count${NC}"
    echo ""
    print_info "Users with passwords:"
    grep -v '^\*\|^!' /etc/shadow 2>/dev/null | cut -d: -f1 | sed "s/^/  ${GRAY}│${NC} /"
else
    print_success "Shadow file is not readable (secure)"
fi
print_separator

# Logged In Users
print_section "Currently Logged In Users"
who_output=$(w 2>/dev/null)
if [ -n "$who_output" ]; then
    echo "$who_output" | sed "s/^/  ${GRAY}│${NC} /"
else
    print_info "No users currently logged in"
fi

echo ""
print_info "Last logins:"
last -n 10 2>/dev/null | sed "s/^/  ${GRAY}│${NC} /"
print_separator

# Sudo Configuration
print_section "Sudo Configuration"
if command -v sudo &> /dev/null; then
    print_success "Sudo is installed"
    sudo_version=$(sudo -V 2>/dev/null | head -n 1)
    print_info "Version: $sudo_version"
    
    # Extract sudo version number
    sudo_ver_num=$(sudo -V 2>/dev/null | grep "Sudo version" | grep -oP '\d+\.\d+\.\d+[a-z]?\d*')
    
    echo ""
    print_warning "Checking for known sudo vulnerabilities..."
    
    # CVE-2021-3156 - Baron Samedit
    if [[ "$sudo_ver_num" =~ ^1\.8\.([2-9]|[1-2][0-9]|3[0-1]) ]] || [[ "$sudo_ver_num" =~ ^1\.9\.[0-5] ]]; then
        print_critical "CVE-2021-3156 (Baron Samedit) - Heap-based buffer overflow"
        echo -e "  ${GRAY}│${NC} ${RED}Severity: CRITICAL${NC}"
        echo -e "  ${GRAY}│${NC} Affected: 1.8.2-1.8.31p2, 1.9.0-1.9.5p1"
        echo -e "  ${GRAY}│${NC} Exploit: https://github.com/blasty/CVE-2021-3156"
        echo ""
    fi
    
    # CVE-2019-14287 - Sudo Bypass
    if [[ "$sudo_ver_num" =~ ^1\.(8\.(0|1[0-9]|2[0-8])|[1-7]\.) ]]; then
        print_warning "CVE-2019-14287 - Sudo security bypass"
        echo -e "  ${GRAY}│${NC} Affected: < 1.8.28"
        echo -e "  ${GRAY}│${NC} Run: sudo -u#-1 id"
        echo ""
    fi
    
    echo ""
    print_info "Attempting to list sudo privileges..."
    sudo -l 2>/dev/null | sed "s/^/  ${GRAY}│${NC} /" || print_warning "Cannot list sudo privileges"
    
    echo ""
    print_info "Checking for NOPASSWD entries in sudoers..."
    if [ -r /etc/sudoers ]; then
        nopasswd_entries=$(grep -E "NOPASSWD" /etc/sudoers 2>/dev/null | grep -v "^#")
        if [ -n "$nopasswd_entries" ]; then
            print_critical "NOPASSWD entries found - potential privilege escalation!"
            echo "$nopasswd_entries" | sed "s/^/  ${GRAY}│${NC} /"
        else
            print_success "No NOPASSWD entries found in main sudoers file"
        fi
    fi
    
    # Check sudoers.d
    if [ -d /etc/sudoers.d ]; then
        echo ""
        print_info "Files in /etc/sudoers.d:"
        ls -la /etc/sudoers.d/ 2>/dev/null | sed "s/^/  ${GRAY}│${NC} /"
        
        # Check for NOPASSWD in sudoers.d files
        for file in /etc/sudoers.d/*; do
            if [ -r "$file" ] && grep -qE "NOPASSWD" "$file" 2>/dev/null; then
                print_warning "NOPASSWD found in: $file"
            fi
        done
    fi
    
    echo ""
    print_info "Checking for sudo token preservation..."
    if [ -d /var/lib/sudo ]; then
        print_info "Sudo token directory exists: /var/lib/sudo"
    fi
else
    print_warning "Sudo is not installed"
    
    # Check for alternatives
    if command -v doas &> /dev/null; then
        print_info "Alternative found: doas"
    fi
fi
print_separator

# Polkit Configuration
print_section "Polkit (PolicyKit) Configuration"
if command -v pkexec &> /dev/null; then
    print_success "Polkit is installed"
    
    # Try to get version
    polkit_version=$(pkexec --version 2>/dev/null | grep -oP '\d+\.\d+' || echo "unknown")
    print_info "Polkit version: ${BOLD}$polkit_version${NC}"
    
    echo ""
    print_warning "Checking for PwnKit vulnerability (CVE-2021-4034)..."
    
    # Check if vulnerable
    if [ -f /usr/bin/pkexec ]; then
        # Check file permissions
        pkexec_perms=$(ls -l /usr/bin/pkexec | cut -d' ' -f1)
        if [[ "$pkexec_perms" =~ ^-rws ]]; then
            print_warning "pkexec has SUID bit set"
            
            # Check version
            if [[ "$polkit_version" =~ ^0\.(9[6-9]|1[0-1][0-9]|120)$ ]] || [ "$polkit_version" = "unknown" ]; then
                print_critical "CVE-2021-4034 (PwnKit) - Memory corruption vulnerability"
                echo -e "  ${GRAY}│${NC} ${RED}Severity: CRITICAL${NC}"
                echo -e "  ${GRAY}│${NC} Affected: All versions from 2009 to January 2022"
                echo -e "  ${GRAY}│${NC} Fixed in: polkit 0.120-1 or later"
                echo -e "  ${GRAY}│${NC} Exploit: https://github.com/arthepsy/CVE-2021-4034"
                echo -e "  ${GRAY}│${NC} Test: Run './pwnkit' or check for 'GCONV_PATH' vulnerability"
                echo ""
            else
                print_success "Polkit version appears to be patched"
            fi
        fi
    fi
    
    # Check polkit configuration
    if [ -d /etc/polkit-1 ]; then
        print_info "Polkit configuration directory: /etc/polkit-1"
        ls -la /etc/polkit-1/ 2>/dev/null | sed "s/^/  ${GRAY}│${NC} /"
    fi
else
    print_info "Polkit (pkexec) not found"
fi
print_separator

# User and Group Enumeration
print_section "Detailed User/Group Mapping"
print_info "Generating full user/group mapping..."
for user in $(cut -d":" -f1 /etc/passwd 2>/dev/null); do
    id "$user" 2>/dev/null
done | sort | sed "s/^/  ${GRAY}│${NC} /"
print_separator

#==============================================================================
# Environment Information
#==============================================================================

print_header "ENVIRONMENT INFORMATION"

print_section "PATH Variable"
echo -e "  ${GRAY}│${NC} ${BOLD}$PATH${NC}"
echo ""
print_info "Checking for writable directories in PATH..."
IFS=':' read -ra PATH_ARRAY <<< "$PATH"
for dir in "${PATH_ARRAY[@]}"; do
    if [ -d "$dir" ] && [ -w "$dir" ]; then
        print_critical "Writable PATH directory: ${BOLD}$dir${NC}"
    fi
done
print_separator

print_section "Environment Variables"
print_info "All environment variables:"
env | sort | sed "s/^/  ${GRAY}│${NC} /"
echo ""
print_warning "Check for sensitive data in environment variables above!"
print_separator

print_section "Shell Configuration Files"
print_info "Checking for readable shell configs..."
for file in ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc /etc/profile /etc/bash.bashrc; do
    if [ -r "$file" ]; then
        print_success "Readable: ${BOLD}$file${NC}"
    fi
done
print_separator

#==============================================================================
# Security Policies
#==============================================================================

print_header "SECURITY POLICIES"

print_section "Password Policy"
if [ -f /etc/login.defs ]; then
    print_success "Found /etc/login.defs"
    grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs 2>/dev/null | sed "s/^/  ${GRAY}│${NC} /"
else
    print_warning "Cannot find password policy file"
fi
print_separator

print_section "Security Modules"
# SELinux
if command -v getenforce &> /dev/null; then
    selinux_status=$(getenforce 2>/dev/null)
    if [ "$selinux_status" = "Enforcing" ]; then
        print_success "SELinux: ${BOLD}$selinux_status${NC}"
    else
        print_warning "SELinux: ${BOLD}$selinux_status${NC}"
    fi
else
    print_info "SELinux not detected"
fi

# AppArmor
if command -v aa-status &> /dev/null; then
    print_info "AppArmor Status:"
    aa-status 2>/dev/null | head -n 10 | sed "s/^/  ${GRAY}│${NC} /"
else
    print_info "AppArmor not detected"
fi

# Firewall
echo ""
print_info "Firewall Status:"
if command -v ufw &> /dev/null; then
    ufw status 2>/dev/null | sed "s/^/  ${GRAY}│${NC} /"
elif command -v firewall-cmd &> /dev/null; then
    firewall-cmd --state 2>/dev/null | sed "s/^/  ${GRAY}│${NC} /"
else
    print_info "No common firewall tool detected"
fi
print_separator

#==============================================================================
# Network Information
#==============================================================================

print_header "NETWORK INFORMATION"

print_section "Network Interfaces"
if command -v ip &> /dev/null; then
    ip a 2>/dev/null | sed "s/^/  ${GRAY}│${NC} /"
elif command -v ifconfig &> /dev/null; then
    ifconfig 2>/dev/null | sed "s/^/  ${GRAY}│${NC} /"
else
    print_error "No network command available"
fi
print_separator

print_section "Routing Table"
if command -v ip &> /dev/null; then
    ip route 2>/dev/null | sed "s/^/  ${GRAY}│${NC} /"
elif command -v route &> /dev/null; then
    route -n 2>/dev/null | sed "s/^/  ${GRAY}│${NC} /"
fi
print_separator

print_section "DNS Configuration"
if [ -f /etc/resolv.conf ]; then
    cat /etc/resolv.conf 2>/dev/null | sed "s/^/  ${GRAY}│${NC} /"
fi
print_separator

print_section "Hosts File"
if [ -f /etc/hosts ]; then
    print_info "Interesting entries in /etc/hosts:"
    cat /etc/hosts 2>/dev/null | grep -v "^#" | grep -v "^$" | sed "s/^/  ${GRAY}│${NC} /"
fi
print_separator

print_section "ARP Cache"
if command -v ip &> /dev/null; then
    ip neigh 2>/dev/null | sed "s/^/  ${GRAY}│${NC} /"
elif command -v arp &> /dev/null; then
    arp -a 2>/dev/null | sed "s/^/  ${GRAY}│${NC} /"
fi
print_separator

print_section "Network Connections"
print_info "Active network connections:"
echo ""
if command -v ss &> /dev/null; then
    ss --ntpu 2>/dev/null | sed "s/^/  ${GRAY}│${NC} /"
elif command -v netstat &> /dev/null; then
    netstat -punta 2>/dev/null | sed "s/^/  ${GRAY}│${NC} /"
else
    print_error "No network stat command available"
fi
print_separator

print_section "Listening Services"
print_info "Services listening on all interfaces:"
echo ""
if command -v ss &> /dev/null; then
    ss -tlnp 2>/dev/null | sed "s/^/  ${GRAY}│${NC} /"
elif command -v netstat &> /dev/null; then
    netstat -tlnp 2>/dev/null | sed "s/^/  ${GRAY}│${NC} /"
fi
print_separator

print_section "Localhost Connections"
print_info "Services listening on localhost:"
echo ""
if command -v ss &> /dev/null; then
    ss --ntpu 2>/dev/null | grep "127.0" | sed "s/^/  ${GRAY}│${NC} /"
elif command -v netstat &> /dev/null; then
    netstat -punta 2>/dev/null | grep "127.0" | sed "s/^/  ${GRAY}│${NC} /"
fi
print_separator

print_section "Firewall Rules"
if command -v iptables &> /dev/null; then
    print_info "IPTables rules:"
    iptables -L -n 2>/dev/null | sed "s/^/  ${GRAY}│${NC} /" || print_warning "Cannot read iptables rules"
fi
print_separator

#==============================================================================
# Running Processes
#==============================================================================

print_header "RUNNING PROCESSES"

print_section "Process List"
print_info "Active processes on the system:"
echo ""
ps aux 2>/dev/null | head -n 30 | sed "s/^/  ${GRAY}│${NC} /"
process_count=$(ps aux 2>/dev/null | wc -l)
echo ""
print_info "Total processes: ${BOLD}$process_count${NC}"
print_info "(Showing first 30 entries)"
print_separator

print_section "Processes Running as Root"
print_info "Processes running with root privileges:"
ps aux 2>/dev/null | grep "^root" | head -n 20 | sed "s/^/  ${GRAY}│${NC} /"
print_separator

print_section "Interesting Processes"
print_info "Looking for interesting processes..."
ps aux 2>/dev/null | grep -iE "sql|apache|nginx|ssh|ftp|mysql|postgres|mongo|redis|docker|tomcat" | grep -v grep | sed "s/^/  ${GRAY}│${NC} /"
print_separator

#==============================================================================
# Scheduled Tasks
#==============================================================================

print_header "SCHEDULED TASKS & PERSISTENCE"

print_section "Cron Jobs"
print_info "User crontab:"
crontab -l 2>/dev/null | grep -v "^#" | sed "s/^/  ${GRAY}│${NC} /" || print_info "No user crontab"

echo ""
print_info "System cron directories:"
ls -la /etc/cron* /etc/at* 2>/dev/null | sed "s/^/  ${GRAY}│${NC} /"

echo ""
print_info "Cron jobs content:"
cat /etc/cron* /etc/at* /etc/anacrontab 2>/dev/null | grep -v "^#" | grep -v "^$" | sed "s/^/  ${GRAY}│${NC} /"

if [ -f /var/spool/cron/crontabs/root ]; then
    echo ""
    print_warning "Root crontab found:"
    cat /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#" | sed "s/^/  ${GRAY}│${NC} /"
fi

echo ""
print_info "Writable cron directories:"
for dir in /etc/cron* /var/spool/cron/*; do
    if [ -d "$dir" ] && [ -w "$dir" ]; then
        print_critical "Writable: ${BOLD}$dir${NC}"
    fi
done
print_separator

print_section "Systemd Timers"
if command -v systemctl &> /dev/null; then
    print_info "Active systemd timers:"
    systemctl list-timers --all 2>/dev/null | sed "s/^/  ${GRAY}│${NC} /"
fi
print_separator

print_section "Systemd Services"
if command -v systemctl &> /dev/null; then
    print_info "Enabled systemd services:"
    systemctl list-unit-files --type=service --state=enabled 2>/dev/null | head -n 20 | sed "s/^/  ${GRAY}│${NC} /"
    
    echo ""
    print_info "Checking for writable service files..."
    for service in $(systemctl list-unit-files --type=service 2>/dev/null | awk '{print $1}' | grep ".service$"); do
        service_path=$(systemctl show -p FragmentPath "$service" 2>/dev/null | cut -d= -f2)
        if [ -n "$service_path" ] && [ -f "$service_path" ] && [ -w "$service_path" ]; then
            print_critical "Writable service: ${BOLD}$service_path${NC}"
        fi
    done
fi
print_separator

print_section "Init Scripts"
print_info "Checking /etc/init.d/:"
ls -la /etc/init.d/ 2>/dev/null | sed "s/^/  ${GRAY}│${NC} /"
print_separator

#==============================================================================
# Installed Software
#==============================================================================

print_header "INSTALLED SOFTWARE"

print_section "Package Managers"
if command -v dpkg &> /dev/null; then
    print_success "dpkg detected"
    pkg_count=$(dpkg -l 2>/dev/null | wc -l)
    print_info "Installed packages: ${BOLD}$pkg_count${NC}"
elif command -v rpm &> /dev/null; then
    print_success "rpm detected"
    pkg_count=$(rpm -qa 2>/dev/null | wc -l)
    print_info "Installed packages: ${BOLD}$pkg_count${NC}"
fi
print_separator

print_section "Security Tools & Utilities"
print_info "Checking for common tools..."
echo ""

tools=("nmap" "nc" "ncat" "netcat" "nc.traditional" "wget" "curl" "ping" 
       "gcc" "g++" "make" "gdb" "base64" "socat" "python" "python2" 
       "python3" "perl" "php" "ruby" "aws" "docker" "lxc" "kubectl"
       "git" "svn" "telnet" "ftp" "ssh" "scp" "rsync" "tmux" "screen"
       "vim" "nano" "emacs" "tcpdump" "wireshark" "strace" "ltrace")

found_tools=0
missing_tools=0

for tool in "${tools[@]}"; do
    if command -v "$tool" &> /dev/null; then
        tool_path=$(which "$tool" 2>/dev/null)
        print_success "${BOLD}$tool${NC} → $tool_path"
        ((found_tools++))
    else
        ((missing_tools++))
    fi
done

echo ""
print_info "Found: ${GREEN}${BOLD}$found_tools${NC} tools"
print_info "Missing: ${GRAY}$missing_tools${NC} tools"
print_separator

print_section "Development Tools"
print_info "Compilers and interpreters:"
for compiler in gcc g++ python python3 perl php ruby java javac node npm; do
    if command -v $compiler &> /dev/null; then
        version=$($compiler --version 2>/dev/null | head -n 1 || echo "Unknown version")
        print_success "$compiler: $version"
    fi
done
print_separator

#==============================================================================
# Container and Virtualization
#==============================================================================

print_header "CONTAINERS & VIRTUALIZATION"

print_section "Docker"
if command -v docker &> /dev/null; then
    print_success "Docker is installed"
    docker --version 2>/dev/null | sed "s/^/  ${GRAY}│${NC} /"
    
    echo ""
    print_info "Docker images:"
    docker images 2>/dev/null | sed "s/^/  ${GRAY}│${NC} /" || print_warning "Cannot list images"
    
    echo ""
    print_info "Docker containers:"
    docker ps -a 2>/dev/null | sed "s/^/  ${GRAY}│${NC} /" || print_warning "Cannot list containers"
    
    echo ""
    print_info "Docker networks:"
    docker network ls 2>/dev/null | sed "s/^/  ${GRAY}│${NC} /" || print_warning "Cannot list networks"
    
    echo ""
    if [ -S /var/run/docker.sock ]; then
        if [ -w /var/run/docker.sock ]; then
            print_critical "Docker socket is writable! Potential privilege escalation!"
        else
            print_info "Docker socket found but not writable"
        fi
    fi
else
    print_info "Docker not installed"
fi
print_separator

print_section "LXC/LXD"
if command -v lxc &> /dev/null; then
    print_success "LXC is installed"
    lxc list 2>/dev/null | sed "s/^/  ${GRAY}│${NC} /" || print_warning "Cannot list containers"
fi

if command -v lxd &> /dev/null; then
    print_success "LXD is installed"
    if groups | grep -q "lxd"; then
        print_critical "User is in 'lxd' group - potential privilege escalation!"
    fi
fi
print_separator

print_section "Kubernetes"
if command -v kubectl &> /dev/null; then
    print_success "kubectl is installed"
    kubectl version --client 2>/dev/null | sed "s/^/  ${GRAY}│${NC} /"
    
    echo ""
    if [ -f ~/.kube/config ]; then
        print_warning "Kubernetes config found: ~/.kube/config"
    fi
fi
print_separator

#==============================================================================
# File System Enumeration
#==============================================================================

print_header "FILE SYSTEM ENUMERATION"

print_section "Writable Directories"
print_info "Searching for world-writable directories (limited search)..."
find / -type d -perm -002 2>/dev/null | grep -vE "^/proc|^/sys|^/dev" | head -n 20 | sed "s/^/  ${GRAY}│${NC} /"
print_separator

print_section "Files Owned by Current User"
current_user=$(whoami)
print_info "Searching for files owned by $current_user (limited search)..."
find /home /opt /var /etc -user "$current_user" 2>/dev/null | head -n 20 | sed "s/^/  ${GRAY}│${NC} /"
print_separator

print_section "Recently Modified Files"
print_info "Files modified in the last 24 hours (limited search)..."
find / -type f -mtime -1 2>/dev/null | grep -vE "^/proc|^/sys|^/dev" | head -n 20 | sed "s/^/  ${GRAY}│${NC} /"
print_separator

print_section "Writable Files in /etc"
print_info "Searching for writable files in /etc..."
find /etc -type f -writable 2>/dev/null | sed "s/^/  ${GRAY}│${NC} /"
if [ ${PIPESTATUS[0]} -eq 0 ] && [ -z "$(find /etc -type f -writable 2>/dev/null)" ]; then
    print_success "No writable files in /etc"
fi
print_separator

print_section "Interesting Files"
print_info "Searching for backup and config files..."
find /home /var/www /opt -type f \( -name "*.bak" -o -name "*.backup" -o -name "*.old" -o -name "*.conf" -o -name "*.config" \) 2>/dev/null | head -n 20 | sed "s/^/  ${GRAY}│${NC} /"
print_separator

print_section "Temporary Directories"
print_info "Files in temporary directories:"
echo ""
print_info "/tmp:"
ls -la /tmp 2>/dev/null | head -n 10 | sed "s/^/  ${GRAY}│${NC} /"

echo ""
print_info "/var/tmp:"
ls -la /var/tmp 2>/dev/null | head -n 10 | sed "s/^/  ${GRAY}│${NC} /"

echo ""
print_info "/dev/shm:"
ls -la /dev/shm 2>/dev/null | head -n 10 | sed "s/^/  ${GRAY}│${NC} /"
print_separator

#==============================================================================
# Credentials & Secrets
#==============================================================================

print_header "CREDENTIALS & SECRETS DISCOVERY"

print_section "SSH Keys"
print_info "Searching for SSH keys..."
for ssh_dir in /home/*/.ssh /root/.ssh ~/.ssh; do
    if [ -d "$ssh_dir" ]; then
        print_warning "SSH directory found: ${BOLD}$ssh_dir${NC}"
        ls -la "$ssh_dir" 2>/dev/null | sed "s/^/    ${GRAY}│${NC} /"
    fi
done
print_separator

print_section "SSH Configuration"
if [ -f ~/.ssh/config ]; then
    print_warning "SSH config found: ~/.ssh/config"
    cat ~/.ssh/config 2>/dev/null | sed "s/^/  ${GRAY}│${NC} /"
fi

if [ -f /etc/ssh/sshd_config ]; then
    print_info "Checking SSH daemon config..."
    grep -iE "PermitRootLogin|PasswordAuthentication|PubkeyAuthentication" /etc/ssh/sshd_config 2>/dev/null | grep -v "^#" | sed "s/^/  ${GRAY}│${NC} /"
fi
print_separator

print_section "Shell History Files"
print_info "Checking for command history files..."
for hist_file in ~/.bash_history ~/.zsh_history ~/.mysql_history ~/.psql_history; do
    if [ -f "$hist_file" ]; then
        print_warning "History file found: ${BOLD}$hist_file${NC}"
        file_size=$(wc -l < "$hist_file" 2>/dev/null)
        print_info "Lines: $file_size"
        
        # Check for interesting commands
        if grep -iE "password|passwd|pass|secret|key|token|api" "$hist_file" &>/dev/null; then
            print_critical "History contains potential credentials!"
        fi
    fi
done
print_separator

print_section "Password Files"
print_info "Searching for common password file names..."
find / -type f \( -name "*password*" -o -name "*passwd*" -o -name "*.pwd" \) 2>/dev/null | grep -vE "^/proc|^/sys|^/usr/share" | head -n 20 | sed "s/^/  ${GRAY}│${NC} /"
print_separator

print_section "Database Files"
print_info "Searching for database files..."
find / -type f \( -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3" \) 2>/dev/null | grep -vE "^/proc|^/sys" | head -n 20 | sed "s/^/  ${GRAY}│${NC} /"
print_separator

print_section "Web Application Configs"
print_info "Searching for web application configuration files..."
find /var/www /opt /srv -type f \( -name "wp-config.php" -o -name "config.php" -o -name "database.yml" -o -name ".env" \) 2>/dev/null | sed "s/^/  ${GRAY}│${NC} /"
print_separator

print_section "Cloud Credentials"
print_info "Checking for cloud provider credentials..."

# AWS
if [ -d ~/.aws ]; then
    print_warning "AWS config directory found: ~/.aws"
    ls -la ~/.aws 2>/dev/null | sed "s/^/  ${GRAY}│${NC} /"
fi

# GCP
if [ -d ~/.config/gcloud ]; then
    print_warning "GCP config directory found: ~/.config/gcloud"
fi

# Azure
if [ -d ~/.azure ]; then
    print_warning "Azure config directory found: ~/.azure"
fi

# Check for cloud credentials in env
if env | grep -iE "AWS_ACCESS|AWS_SECRET|GOOGLE_APPLICATION|AZURE" &>/dev/null; then
    print_critical "Cloud credentials found in environment variables!"
fi
print_separator

print_section "Git Credentials"
if [ -f ~/.git-credentials ]; then
    print_warning "Git credentials file found: ~/.git-credentials"
fi

if [ -f ~/.gitconfig ]; then
    print_info "Git config found:"
    cat ~/.gitconfig 2>/dev/null | sed "s/^/  ${GRAY}│${NC} /"
fi

print_info "Searching for .git directories..."
find / -type d -name ".git" 2>/dev/null | head -n 10 | sed "s/^/  ${GRAY}│${NC} /"
print_separator

#==============================================================================
# Cloud Metadata Services
#==============================================================================

print_header "CLOUD METADATA SERVICES"

print_section "AWS Metadata"
print_info "Attempting to query AWS metadata service..."
if timeout 2 curl -s http://169.254.169.254/latest/meta-data/ &>/dev/null; then
    print_warning "AWS metadata service is accessible!"
    timeout 2 curl -s http://169.254.169.254/latest/meta-data/ 2>/dev/null | sed "s/^/  ${GRAY}│${NC} /"
    
    echo ""
    print_info "Instance identity:"
    timeout 2 curl -s http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null | sed "s/^/  ${GRAY}│${NC} /"
    
    echo ""
    print_info "IAM role:"
    timeout 2 curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null | sed "s/^/  ${GRAY}│${NC} /"
else
    print_info "AWS metadata service not accessible"
fi
print_separator

print_section "GCP Metadata"
print_info "Attempting to query GCP metadata service..."
if timeout 2 curl -s -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/ &>/dev/null; then
    print_warning "GCP metadata service is accessible!"
    timeout 2 curl -s -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/ 2>/dev/null | sed "s/^/  ${GRAY}│${NC} /"
else
    print_info "GCP metadata service not accessible"
fi
print_separator

print_section "Azure Metadata"
print_info "Attempting to query Azure metadata service..."
if timeout 2 curl -s -H "Metadata: true" http://169.254.169.254/metadata/instance?api-version=2021-02-01 &>/dev/null; then
    print_warning "Azure metadata service is accessible!"
    timeout 2 curl -s -H "Metadata: true" http://169.254.169.254/metadata/instance?api-version=2021-02-01 2>/dev/null | sed "s/^/  ${GRAY}│${NC} /"
else
    print_info "Azure metadata service not accessible"
fi
print_separator

#==============================================================================
# Privileged Binaries
#==============================================================================

print_header "PRIVILEGED BINARIES & CAPABILITIES"

print_section "SUID Binaries (User Elevation)"
print_warning "Searching for SUID binaries (may take a while)..."
echo ""

suid_files=$(find / -perm -4000 -type f 2>/dev/null)
suid_count=$(echo "$suid_files" | grep -c .)

if [ -n "$suid_files" ] && [ "$suid_count" -gt 0 ]; then
    echo "$suid_files" | while read file; do
        file_owner=$(ls -l "$file" 2>/dev/null | awk '{print $3}')
        if [ "$file_owner" = "root" ]; then
            print_warning "${BOLD}$file${NC} (owner: $file_owner)"
        else
            print_info "$file (owner: $file_owner)"
        fi
    done
    echo ""
    print_info "Total SUID binaries found: ${BOLD}$suid_count${NC}"
    print_warning "Check GTFOBins for SUID exploitation: https://gtfobins.github.io/"
else
    print_info "No SUID binaries found"
fi
print_separator

print_section "SGID Binaries (Group Elevation)"
print_info "Searching for SGID binaries..."
echo ""

sgid_files=$(find / -perm -2000 -type f 2>/dev/null | head -n 20)
if [ -n "$sgid_files" ]; then
    echo "$sgid_files" | sed "s/^/  ${GRAY}│${NC} /"
    echo ""
    print_info "(Showing first 20 entries)"
else
    print_info "No SGID binaries found"
fi
print_separator

print_section "File Capabilities"
print_info "Searching for files with capabilities..."
if command -v getcap &> /dev/null; then
    getcap -r / 2>/dev/null | sed "s/^/  ${GRAY}│${NC} /"
    if [ ${PIPESTATUS[0]} -eq 0 ] && [ -z "$(getcap -r / 2>/dev/null)" ]; then
        print_info "No capabilities found"
    fi
else
    print_warning "getcap not available"
fi
print_separator

#==============================================================================
# NFS and Shares
#==============================================================================

print_header "NETWORK SHARES"

print_section "NFS Exports"
if [ -f /etc/exports ]; then
    print_info "NFS exports configuration:"
    cat /etc/exports 2>/dev/null | grep -v "^#" | sed "s/^/  ${GRAY}│${NC} /"
    
    if grep -q "no_root_squash" /etc/exports 2>/dev/null; then
        print_critical "NFS share with no_root_squash found - privilege escalation possible!"
    fi
else
    print_info "No NFS exports configured"
fi
print_separator

print_section "Mounted Filesystems"
print_info "Currently mounted filesystems:"
mount 2>/dev/null | sed "s/^/  ${GRAY}│${NC} /"

echo ""
print_info "Checking for interesting mount options..."
if mount | grep -iE "noexec|nosuid" &>/dev/null; then
    print_success "Security mount options detected"
fi
print_separator

#==============================================================================
# Kernel Modules
#==============================================================================

print_header "KERNEL MODULES"

print_section "Loaded Kernel Modules"
print_info "Currently loaded modules:"
lsmod 2>/dev/null | head -n 20 | sed "s/^/  ${GRAY}│${NC} /"
echo ""
print_info "(Showing first 20 entries)"
print_separator

print_section "Modprobe Configuration"
if [ -d /etc/modprobe.d ]; then
    print_info "Modprobe configs:"
    ls -la /etc/modprobe.d/ 2>/dev/null | sed "s/^/  ${GRAY}│${NC} /"
fi
print_separator

#==============================================================================
# Summary and Recommendations
#==============================================================================

print_header "ENUMERATION COMPLETE"

# Close HTML sections
html_append "            </div>"

# Add summary statistics to HTML
if [ "$OUTPUT_HTML" = true ]; then
    html_append "            <div class=\"section\" id=\"summary\">"
    html_append "                <h2 class=\"section-title\">📊 Summary Statistics</h2>"
    html_append "                <div class=\"stats-grid\">"
    html_append "                    <div class=\"stat-card\">"
    html_append "                        <div class=\"stat-number\">$(date +%Y-%m-%d)</div>"
    html_append "                        <div class=\"stat-label\">Scan Date</div>"
    html_append "                    </div>"
    html_append "                    <div class=\"stat-card\">"
    html_append "                        <div class=\"stat-number\">$(whoami)</div>"
    html_append "                        <div class=\"stat-label\">User Context</div>"
    html_append "                    </div>"
    html_append "                    <div class=\"stat-card\">"
    html_append "                        <div class=\"stat-number\">$(hostname)</div>"
    html_append "                        <div class=\"stat-label\">Target Host</div>"
    html_append "                    </div>"
    html_append "                    <div class=\"stat-card\">"
    html_append "                        <div class=\"stat-number\">${SECONDS}s</div>"
    html_append "                        <div class=\"stat-label\">Execution Time</div>"
    html_append "                    </div>"
    html_append "                </div>"
    html_append "            </div>"
fi

output ""
output "${GREEN}${BOLD}✓ Comprehensive enumeration finished${NC}"
output "${GRAY}Completed: $(date)${NC}"
output "${GRAY}Execution time: ${SECONDS} seconds${NC}"
output ""

# Display output file locations
if [ "$OUTPUT_TEXT" = true ] || [ "$OUTPUT_HTML" = true ]; then
    output "${CYAN}${BOLD}📁 Reports Generated:${NC}"
    if [ "$OUTPUT_TEXT" = true ]; then
        output "${GREEN}  ✓ Text Report:${NC} $TEXT_OUTPUT"
    fi
    if [ "$OUTPUT_HTML" = true ]; then
        output "${GREEN}  ✓ HTML Report:${NC} $HTML_OUTPUT"
    fi
    output ""
fi

output "${YELLOW}${BOLD}Key Areas to Review:${NC}"
output "  ${GRAY}•${NC} ${RED}Critical findings marked with [!!!]${NC}"
output "  ${GRAY}•${NC} ${YELLOW}Warnings marked with [!]${NC}"
output "  ${GRAY}•${NC} SUID/SGID binaries for privilege escalation"
output "  ${GRAY}•${NC} Writable files in sensitive directories"
output "  ${GRAY}•${NC} Credentials in configuration files"
output "  ${GRAY}•${NC} Command history for sensitive information"
output "  ${GRAY}•${NC} Cron jobs and scheduled tasks"
output "  ${GRAY}•${NC} Network services and open ports"
output "  ${GRAY}•${NC} Docker/container configurations"
output "  ${GRAY}•${NC} Cloud metadata service access"
output ""
output "${YELLOW}${BOLD}Useful Resources:${NC}"
output "  ${GRAY}•${NC} GTFOBins: https://gtfobins.github.io/"
output "  ${GRAY}•${NC} PEASS-ng: https://github.com/carlospolop/PEASS-ng"
output "  ${GRAY}•${NC} HackTricks: https://book.hacktricks.xyz/"
output "  ${GRAY}•${NC} PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings"
output ""
output "${CYAN}╔═══════════════════════════════════════════════════════════════════════════╗${NC}"
output "${CYAN}║${NC}  ${GRAY}Remember: Only use this tool on systems you are authorized to test${NC}     ${CYAN}║${NC}"
output "${CYAN}╚═══════════════════════════════════════════════════════════════════════════╝${NC}"
output ""

# Close HTML report
if [ "$OUTPUT_HTML" = true ]; then
    html_append "        </div>"
    html_append "        <div class=\"footer\">"
    html_append "            <p><strong>Linux System Enumeration Report</strong></p>"
    html_append "            <p>Generated on $(date)</p>"
    html_append "            <p>⚠️ For Authorized Security Assessments Only ⚠️</p>"
    html_append "            <p style=\"margin-top: 20px; opacity: 0.7;\">Execution Time: ${SECONDS} seconds | User: $(whoami) | Host: $(hostname)</p>"
    html_append "        </div>"
    html_append "    </div>"
    html_append "</body>"
    html_append "</html>"
    
    if [ "$QUIET_MODE" = false ]; then
        echo -e "${GREEN}HTML report saved to: ${BOLD}$HTML_OUTPUT${NC}"
    fi
fi

if [ "$OUTPUT_TEXT" = true ] && [ "$QUIET_MODE" = false ]; then
    echo -e "${GREEN}Text report saved to: ${BOLD}$TEXT_OUTPUT${NC}"
fi
