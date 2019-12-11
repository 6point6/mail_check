import os, sys
import checkdmarc

def check_DMARC(domain):
    print("Checking DMARC for \"%s\"" % domain)

    dmarc = {}
    
    try:
        dmarc = checkdmarc.get_dmarc_record(domain, timeout=10.0, nameservers=["8.8.8.8", "1.1.1.1"])
        
        #print(dmarc)

        # location
        print("Location: \t%s" % dmarc["location"])

        # record
        print("Raw Record: \t%s" % dmarc["record"])

        # parsed
        parsed = dmarc["parsed"]

        # version
        print("Version: \t%s" % parsed["tags"]["v"]["value"])

        # get DKIM
        print("DKIM explicit: \t%s" % parsed["tags"]["adkim"]["explicit"])
        
        # Get SPF
        print("SPF explicit: \t%s" % parsed["tags"]["aspf"]["explicit"])
        if parsed["tags"]["aspf"]["explicit"] is True:
            print("SPF Value: \t%s" % parsed["tags"]["aspf"]["value"])
        
        # print all the dicts anyway
        #print("\nAll data:")
        #for key in parsed["tags"]:
           #print("%s: %s" % (key, parsed["tags"][key]))
        
        print("\n")

    except Exception as e:
        print('Error with ' + domain)
        print(e)


# TODO fix this
def check_domain(domain):
    print("Checking domain records for \"%s\"" % domain)
    dmarc = {}
    
    try:
        dmarc = checkdmarc.check_domains(domain, timeout=10.0, nameservers=["8.8.8.8", "1.1.1.1"])
        
        print(dmarc)
    except Exception as e:
            print('Error with ' + domain)
            print(e)
    
    print("\n")


def get_hosts(domain):
    dmarc = {}
    
    try:
        dmarc = checkdmarc.get_mx_hosts(domain, timeout=10.0, nameservers=["8.8.8.8", "1.1.1.1"])
        
        print(dmarc)

        # TODO parse this
    except Exception as e:
            print('Error with ' + domain)
            print(e)

    print("\n")


def check_SPF(pure_domain):
    dmarc = {}
    
    try:
        dmarc = checkdmarc.query_spf_record(domain, timeout=10.0, nameservers=["8.8.8.8", "1.1.1.1"])
        
        print("SPF Record: %s" % dmarc["record"])

        #print("Warning: %s" % dmarc["warnings"])

        # TODO parse this
    except Exception as e:
            print('Error with ' + domain)
            print(e)
    
    print("\n")


if __name__ == '__main__':
    if len(sys.argv) is not 2:
        print("Usage: python3 mail_check.py domain")
        sys.exit(-1)
    
    domain = sys.argv[1]

    pure_domain = checkdmarc.get_base_domain(domain)
    print("Pure domain = \"%s\"" % pure_domain)

    get_hosts(pure_domain)
    check_DMARC(pure_domain)
    check_domain(pure_domain)
    check_SPF(pure_domain)
    