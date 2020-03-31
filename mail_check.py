# See https://www.ncsc.gov.uk/information/mailcheck for the NCSC version
# For more info see https://dmarc.org/overview/, https://tools.ietf.org/html/rfc4408, https://tools.ietf.org/html/rfc6376
import os, sys
import checkdmarc
from dmarc import process_DMARC, check_DMARC_order


# TODO fix this
def check_domain(domain):
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


def check_SPF(pure_domain):
    print("==== SPF ====")
    dmarc = {}
    
    try:
        dmarc = checkdmarc.query_spf_record(domain, timeout=10.0, nameservers=["8.8.8.8", "1.1.1.1"])
        
        print("SPF Record: %s\n" % dmarc["record"])

        for warning in dmarc["warnings"]:
            print("Warning: \"%s\"" % warning)

        # TODO parse this
    except Exception as e:
            print('Error with ' + domain)
            print(e)
    
    print("\n")


if __name__ == '__main__':
    if len(sys.argv) is not 2:
        print("Usage: python3 mail_check.py domain")
        sys.exit(-1)
    
    # check domain
    domain = sys.argv[1]
    pure_domain = checkdmarc.get_base_domain(domain)
    print("Pure domain = \"%s\"\n" % pure_domain)

    # run tests
    #get_hosts(pure_domain)
    process_DMARC(pure_domain)
    #check_domain(pure_domain)
    #check_SPF(pure_domain)
    