import os, sys
import checkdmarc

def check(domain):
    print("Checking \"%s\"" % domain)

    pure_domain = checkdmarc.get_base_domain(domain)
    print("Pure domain = \"%s\"" % pure_domain)

    dmarc = {}
    try:
        dmarc = checkdmarc.get_dmarc_record(pure_domain, timeout=10.0, nameservers=["8.8.8.8", "1.1.1.1"])
        
        #print(dmarc)

        # record
        for key in dmarc["record"]:
            

        for dict_name in dmarc:
            print(dict_name)

    except Exception as e:
        print('Error with ' + domain)
        print(e)

if __name__ == '__main__':
    if len(sys.argv) is not 2:
        print("Usage: python3 mail_check.py domain")
        sys.exit(-1)
    
    domain = sys.argv[1]
    check(domain)