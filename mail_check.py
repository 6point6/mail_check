#!/usr/bin/python3

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


# read the list file, return list of domains
def get_domain_list_from_file(input_file):
    domains = []

    with open(input_file) as f:
        
        lines = f.readlines()

        for line in lines:
            domain = line.strip()
            pure_domain = checkdmarc.get_base_domain(domain)

            if pure_domain not in domains:
                domains.append(pure_domain)
    
    return domains


# test a single domain
def test_domain(domain, force):
    # run tests
    process_DMARC(domain)
    process_SPF(domain)

    if force:
        get_hosts(domain)
        # TODO re-enable this when fixed
        #get_domains(pure_domain)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Mail record checking utility')
    parser.add_argument('-d', type=str, help='The domain record to test')
    parser.add_argument('-l', type=str, help='File of domains to test, one domain per line')
    parser.add_argument('-f', action='store_true', default=False, help='Run all tests')
    args = parser.parse_args()

    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(-1)

    # check domain
    if (args.d is None and args.l is None) or (args.d is not None and args.l is not None) :
        print("Error: Must enter either a domain or a list\n")
        parser.print_help()
        sys.exit(-1)
    
    if args.d is not None:
        domain = args.d
        pure_domain = checkdmarc.get_base_domain(domain)
        print("Pure domain = \"%s\"\n" % pure_domain)

        test_domain(pure_domain, args.f)
    elif args.l is not None:
        dfile = args.l
        
        if os.path.isfile(dfile):
            domains = get_domain_list_from_file(dfile)
            print("Found %d unique pure domains to test" % len(domains))

            for domain in domains:
                print("\n==============================Testing %s==============================" % domain)
                test_domain(domain, args.f)
        else:
            print("File %s not found" % dfile)
            sys.exit(-1)

        
       


    
    
    
        
        
    