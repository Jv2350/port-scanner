import nmap
import os
import sys


def main():
    nm = nmap.PortScanner()

    target = "45.33.32.156"

    # SYN scan and OS detection both require elevated privileges.  If you run this script as a normal user it will fail with the error you saw earlier resulting in an "empty XML" parse error downstream.  Either run with sudo or change the options to a non‑privileged scan type such as -sT.
    options = "-sS -sV -O scan_results"

    try:
        nm.scan(target, arguments=options)
    except nmap.PortScannerError as err:
        msg = str(err)
        print("nmap error:", msg)
        if "requires root privileges" in msg:
            print("This scan type needs root.\n" \
                  "1. Run the script with sudo, or\n" \
                  "2. switch to a non‑privileged scan (e.g. use '-sT' instead of '-sS').")
            sys.exit(1)
        else:
            # re‑raise unexpected errors
            raise

    for host in nm.all_hosts():
        print(f"Host: {host} ({nm[host].hostname()})")
        print(f"State: {nm[host].state()}")

        for proto in nm[host].all_protocols():
            print(f"Protocol: {proto}")

            lport = nm[host][proto].keys()
            for port in lport:
                print(f"Port: {port}\tState: {nm[host][proto][port]['state']}\tService: {nm[host][proto][port]['name']}")


if __name__ == "__main__":
    main()
