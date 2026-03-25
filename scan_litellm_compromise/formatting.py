"""ANSI formatting and display helpers."""

RED = "\033[0;31m"
YELLOW = "\033[1;33m"
GREEN = "\033[0;32m"
CYAN = "\033[0;36m"
BOLD = "\033[1m"
RESET = "\033[0m"


def print_banner():
    print(f"{CYAN}{BOLD}")
    print("+" + "=" * 63 + "+")
    print("|   LiteLLM Supply Chain Attack Scanner (Python)              |")
    print("|   Compromised versions: v1.82.7, v1.82.8                    |")
    print("|   Campaign: TeamPCP -- March 24, 2026                       |")
    print("+" + "=" * 63 + "+")
    print(RESET)


def print_separator():
    print(f"{CYAN}{'─' * 63}{RESET}")


def print_phase_header(number: int, title: str):
    print(f"\n{BOLD}[Phase {number}] {title}{RESET}\n")


def print_ioc_found(path: str):
    print(f"  {RED}{BOLD}! FOUND IOC:{RESET} {path}")


def print_clean(message: str = "None found"):
    print(f"  {GREEN}+ {message}{RESET}")


def print_check_header(description: str):
    print(f"  {BOLD}Checking for {description}...{RESET}")
