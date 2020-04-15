# See https://www.ncsc.gov.uk/information/mailcheck for the NCSC version
# For more info see https://dmarc.org/overview/, https://tools.ietf.org/html/rfc4408, https://tools.ietf.org/html/rfc6376
import os, sys
import checkdmarc
import argparse

from dmarc import process_DMARC, check_DMARC_order
from spf import process_SPF


# TODO fix this
def get_domains(domain):
    print("==== Domains ====")
    dmarc = {}
    
    try:
        dmarc = checkdmarc.check_domains(domain, timeout=10.0, nameservers=["8.8.8.8", "1.1.1.1"])
        
        if len(dmarc) > 0:
            print(dmarc)
        else:
            print("None found")
    except Exception as e:
            print('Error with ' + domain)
            print(e)
    
    print("\n")


# Retrieve and print all the MX host entries
def get_hosts(domain):
    print("==== Hosts ====")
    dmarc = {}
    
    try:
        dmarc = checkdmarc.get_mx_hosts(domain, timeout=10.0, nameservers=["8.8.8.8", "1.1.1.1"])
        
        for host_record in dmarc["hosts"]:
            print("Hostname: %s, preference: %s, TLS: %s, starttls: %s." % (host_record["hostname"], host_record["preference"], host_record["tls"], host_record["starttls"]))
            print("Addresses: ", end="")

            for address in host_record["addresses"]:
                print("%s, " % address, end="")
            
            print("\n")

        for warning in dmarc["warnings"]:
            print("Warning: %s" % warning)
    except Exception as e:
            print('Error with ' + domain)
            print(e)

    print()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Mail record checking utility')
    parser.add_argument('-d', type=str, help='The domain record to test')
    parser.add_argument('-f', action='store_true', help='Run all tests')
    args = parser.parse_args()

    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(-1)

    # check domain
    domain = args.d
    pure_domain = checkdmarc.get_base_domain(domain)
    print("Pure domain = \"%s\"\n" % pure_domain)

    # run tests
    process_DMARC(pure_domain)
    process_SPF(pure_domain)

    if args.f:
        get_hosts(pure_domain)
        # TODO re-enable this when fixed
        #get_domains(pure_domain)
        
        
    