import checkdmarc
from tabulate import tabulate
import collections

VERSION_INDEX = 0
P_INDEX = 1

dmarcRecord = collections.namedtuple("DMARC_Record", "location, record, v, p_explicit, p_value, rua_explicit, rua_value, ruf_explicit, ruf_defined, pct_explicit, pct_value, sp_explicit, sp_value, adkim_explicit, adkim_value, aspf_explicit, aspf_value, fo_explicit, fo_value, rf_explicit, rf_value, ri_explicit, ri_value")

# explanations stolen from https://dmarcian.com/dmarc-inspector/ and https://www.validity.com/blog/demystifying-the-dmarc-record/
def process_DMARC(domain):
    print("==== DMARC ====")

    dmarc = {}
    
    try:
        dmarc = checkdmarc.get_dmarc_record(domain, timeout=10.0, nameservers=["8.8.8.8", "1.1.1.1"])
        parsedRecord = dmarcRecord
        
        #print(dmarc)  

        check_DMARC_order(dmarc["record"])

        # location
        parsedRecord.location = dmarc["location"]

        # record
        parsedRecord.record = dmarc["record"]

        # parsed
        parsed = dmarc["parsed"]

        # version
        # The DMARC version should always be "DMARC1".
        # Note: A wrong, or absent DMARC version tag would cause the entire record to be ignored
        parsedRecord.version = parsed["tags"]["v"]["value"]

        # p
        # Policy applied to emails that fails the DMARC check. Authorized values: "none", "quarantine", or "reject". 
        # "none" is used to collect feedback and gain visibility into email streams without impacting existing flows. 
        # "quarantine" allows Mail Receivers to treat email that fails the DMARC check as suspicious. Most of the time, they will end up in your SPAM folder. 
        # "reject" outright rejects all emails that fail the DMARC check.
        parsedRecord.p_explicit = parsed["tags"]["p"]["explicit"]
        parsedRecord.p_value = parsed["tags"]["p"]["value"]

        # get ADKIM
        # 
        if "adkim" in parsed["tags"]:
            parsedRecord.adkim_explicit = parsed["tags"]["adkim"]["explicit"]
            parsedRecord.adkim_value = parsed["tags"]["adkim"]["value"]
        else:
            parsedRecord.adkim_explicit = "Not Defined"
            parsedRecord.adkim_value = "Not Defined"
        
        # Get ASPF
        # Specifies “Alignment Mode” for SPF.
        # Authorized values: “r”, “s”. “r”, or “Relaxed Mode” allows SPF Authenticated domains that share a common Organizational Domain with an email’s “header-From:” domain to pass the DMARC check. “s”, or “Strict Mode” requires exact matching between the SPF domain and an email’s “header-From:” domain.
        if "aspf" in parsed["tags"]:
            parsedRecord.aspf_explicit = parsed["tags"]["aspf"]["explicit"]
            parsedRecord.aspf_value = parsed["tags"]["aspf"]["value"]
        else:
            parsedRecord.aspf_explicit = "Not Defined"
            parsedRecord.aspf_value = "Not Defined"
        

        # rua
        # The list of URIs for receivers to send XML feedback to.
        # Note: This is not a list of email addresses, as DMARC requires a list of URIs of the form “mailto:address@example.org”.
        if "rua" in parsed["tags"]:
            parsedRecord.rua_explicit = parsed["tags"]["rua"]["explicit"]
            parsedRecord.rua_value = ""

            for entry in parsed["tags"]["rua"]["value"]:
                parsedRecord.rua_value = parsedRecord.rua_value + "Address: " + entry["address"] + ",\nscheme: " + entry["scheme"]
        else:
            parsedRecord.rua_explicit = "Not Defined"
            parsedRecord.rua_value = "Not Defined"

        # ruf
        # The list of URIs for receivers to send Forensic reports to.
        # Note: This is not a list of email addresses, as DMARC requires a list of URIs of the form “mailto:address@example.org”.
        if "ruf" in parsed["tags"]:
            parsedRecord.ruf_explicit = parsed["tags"]["ruf"]["explicit"]
            parsedRecord.ruf_value = ""

            for entry in parsed["tags"]["ruf"]["value"]:
                parsedRecord.ruf_value = parsedRecord.ruf_value + "Address: %s, scheme: %s" % (entry["address"], entry["scheme"])
        else:
            parsedRecord.ruf_explicit = "Not Defined"
            parsedRecord.ruf_value = "Not Defined"

        # pct
        # The percentage tag tells receivers to only apply policy against email that fails the DMARC check x amount of the time. 
        # For example, "pct=25" tells receivers to apply the "p=" policy 25% of the time against email that fails the DMARC check. 
        # Note: The policy must be "quarantine" or "reject" for the percentage tag to be applied.
        parsedRecord.pct_explicit = parsed["tags"]["pct"]["explicit"]
        parsedRecord.pct_value = parsed["tags"]["pct"]["value"]

        # sp
        # Policy to apply to email from a sub-domain of this DMARC record that fails the DMARC check.
        # Authorized values: "none", "quarantine", or "reject".
        # This tag allows domain owners to explicitly publish a "wildcard" sub-domain policy.
        parsedRecord.sp_explicit = parsed["tags"]["sp"]["explicit"]
        parsedRecord.sp_value = parsed["tags"]["sp"]["value"]

        # fo
        # 0: Generate a DMARC failure report if all underlying authentication mechanisms fail to produce an aligned “pass” result. (Default)
        # 1: Generate a DMARC failure report if any underlying authentication mechanism produced something other than an aligned “pass” result.
        # d: Generate a DKIM failure report if the message had a signature that failed evaluation, regardless of its alignment.
        # s: Generate an SPF failure report if the message failed SPF evaluation, regardless of its alignment.
        parsedRecord.fo_explicit = parsed["tags"]["fo"]["explicit"]
        parsedRecord.fo_value = parsed["tags"]["fo"]["value"][0]

        # rf
        # The reporting format for individual forensic reports. Authorized values: “afrf”, “iodef”.
        parsedRecord.rf_explicit = parsed["tags"]["rf"]["explicit"]
        parsedRecord.rf_value = parsed["tags"]["rf"]["value"][0]

        if parsedRecord.rf_value != "afrf" and parsedRecord.rf_value !=  "iodef":
            print("Problem found: Report format not afrf or iodef")
        
        # ri
        # The reporting interval for how often you’d like to receive aggregate XML reports.
        # You’ll most likely receive reports once a day regardless of this setting.
        parsedRecord.ri_explicit = parsed["tags"]["ri"]["explicit"]
        parsedRecord.ri_value = parsed["tags"]["ri"]["value"]

        print(tabulate([["Location", parsedRecord.location], 
        ["Version", parsedRecord.version], 
        ["Raw Record", parsedRecord.record]],
        headers=["Field", "Value"], colalign=("left",)))

        print("\nFields:\n")

        print(tabulate([
        ["p", parsedRecord.p_explicit, parsedRecord.p_value, get_policy_words(parsedRecord.p_value)],
        ["adkim", parsedRecord.adkim_explicit, parsedRecord.adkim_value, get_alignment_words(parsedRecord.adkim_value)],
        ["aspf", parsedRecord.aspf_explicit, parsedRecord.aspf_value, get_alignment_words(parsedRecord.aspf_value)],
        ["rua", parsedRecord.rua_explicit, parsedRecord.rua_value, "Indicates where aggregate DMARC reports should be sent to."],
        ["ruf", parsedRecord.ruf_explicit, parsedRecord.ruf_value, "Indicates where forensic DMARC reports should be sent to."],
        ["pc", parsedRecord.pct_explicit, parsedRecord.pct_value, "Percentage of messages to which the DMARC policy is to be applied.\nThis parameter provides a way to gradually\nimplement and test the impact of the policy."],
        ["sp", parsedRecord.sp_explicit, parsedRecord.sp_value, get_sp_policy_words(parsedRecord.sp_value)],
        ["fo", parsedRecord.fo_explicit, parsedRecord.fo_value, get_fo_words(parsedRecord.fo_value)],
        ["rf", parsedRecord.rf_explicit, parsedRecord.rf_value, "The reporting format for individual Forensic reports.\nAuthorized values: “afrf”, “iodef”."],
        ["ri", parsedRecord.ri_explicit, parsedRecord.ri_value, "The number of seconds elapsed between\nsending aggregate reports to the sender.\nThe default value is 86,400 seconds or a day."]
        ], headers=["Key", "Set", "Value", "Comment"], colalign=("left",)))

        print()

    except Exception as e:
        print('Error with processing record for %s: %s' % (domain, e))


# check the order of the version and p fields
def check_DMARC_order(record):
    # e.g.: v=DMARC1; rua=mailto:55d7175f07@rep.dmarcanalyzer.com; p=none; pct=100; sp=none; adkim=r; aspf=r;
    
    # strip spaces out
    record = record.replace(" ", "")
    
    # split the entries
    entries = record.split(";")
    
    #print("DMARC record has %d entries" % len(entries))

    # version should be first
    if not entries[VERSION_INDEX][0:2] == "v=":
        print("Problem found: first entry should be version\n")
    else:
        # should be v1    
        if not entries[VERSION_INDEX] == "v=DMARC1":
            print("Problem found: unknown version \"%s\"\n" % entries[VERSION_INDEX][2:])

    # p should be second
    if not entries[P_INDEX][0:2] == "p=":
        print("Problem found: second entry should be 'p',currently set to \"%s\"\n" % entries[P_INDEX])

        # find p
        for entry in entries:
            if entry[0:2] == "p=":
                check_p_value(entry[2:])
    else:
        check_p_value(entries[P_INDEX][2:])


# check the policy value
def check_p_value(p_value):
    if p_value == "none":
        # stolen from https://dmarcian.com/dmarc-inspector/
        print("Problem found: DMARC record \"p\" tag is set to \"none\", which does not prevent abuse on your domain. If you are satisfied with the authentication success of your sending sources, move your policy to a 'p=quarantine' or 'p=reject'.")
    elif p_value != "quarantine" and p_value != "reject":
        print("Problem found: 'p' should be set to 'none', 'quarantine' or 'reject'")


# Get a text explanation of the policy value
def get_policy_words(p_value):
    if p_value == "none":
        return "No specific action be taken on mail\nthat fails DMARC authentication and alignment."
    elif p_value == "quarantine":
        return "Mail failing the DMARC authentication and alignment\nchecks be treated as suspicious by mail receivers.\nThis can mean receivers place the email in the spam/junk folder,\n flag as it suspicious \nor scrutinize this mail with extra intensity."
    elif p_value == "reject":
        return "Reject the email that fails \nthe DMARC authentication and alignment checks.\n Rejection should occur during the SMTP transaction.\nThis is the most strict policy and\noffers the highest level of protection."
    else:
        return "Unknown"


# Get a text explanation of the policy value
def get_sp_policy_words(p_value):
    if p_value == "none":
        return "(Sub-Domains) No specific action be taken on mail\nthat fails DMARC authentication and alignment."
    elif p_value == "quarantine":
        return "(Sub-Domains) Mail failing the DMARC authentication and alignment\nchecks be treated as suspicious by mail receivers.\nThis can mean receivers place the email in the spam/junk folder,\nflag as it suspicious\nor scrutinize this mail with extra intensity."
    elif p_value == "reject":
        return "(Sub-Domains) Reject the email that fails \nthe DMARC authentication and alignment checks.\nRejection should occur during the SMTP transaction.\nThis is the most strict policy and\noffers the highest level of protection."
    else:
        return "Unknown"


#
def get_fo_words(fo_value):
    if fo_value == "0":
        return "Generate a DMARC failure report if all\nunderlying authentication mechanisms\nfail to produce an aligned “pass” result. (Default)"
    elif fo_value == "1":
        return "Generate a DMARC failure report if any\n underlying authentication mechanism\nproduced something other than\nan aligned “pass” result."
    elif fo_value == "d":
        return "Generate a DKIM failure report if the\nmessage had a signature that\n failed evaluation, regardless\nof its alignment."
    elif fo_value == "s":
        return "Generate an SPF failure report\n if the message failed SPF evaluation,\nregardless of its alignment."
    else:
        return "Unknown"


def get_alignment_words(value):
    if value == "r":
        return "Relaxed Mode allows Authenticated DKIM/SPF domains\nthat share a common Organizational Domain\nwith an email's \"header-From:\"\ndomain to pass the DMARC check."
    elif value == "s":
        return "Strict Mode requires exact matching between\nthe DKIM/SPF d= domain and an email's \"header-From:\" domain."






