#! /usr/bin/env python
# -*- coding: iso-8859-1 -*-
import datetime
import sys
import os
import subprocess
import time
import logging
import getopt
import re
import urllib2
from elasticsearch import Elasticsearch
from dns import resolver, reversename

resolver = resolver.Resolver()
resolver.timeout = 1
resolver.lifetime = 1
resolver.nameservers = ['8.8.8.8', '8.8.4.4']
resolve_ipaddress = True
es_nodes = ["es-01.dbap.de"]
path_to_queries_file = os.path.dirname(os.path.realpath(__file__))
now = now = datetime.datetime.now()
index_name = 'gambolputty-%d.%02d.%02d' % (now.year, now.month, now.day)
min_count = 0
query_name = None
country_code = None
ip_list_url = None
execute_blocking = False
iptables_action = 'REJECT'
ip_whitelist = ['62.225.111.26', '172.', '195.137.225', '195.137.224']

countries = {
    "af": "Afghanistan",
    "al": "Albania",
    "dz": "Algeria",
    "as": "American Samoa",
    "ad": "Andorra",
    "ao": "Angola",
    "ap": "Asia/Pacific Region",
    "ai": "Anguilla",
    "aq": "Antarctica",
    "ag": "Antigua and Barbuda",
    "ar": "Argentina",
    "am": "Armenia",
    "aw": "Aruba",
    "au": "Australia",
    "at": "Austria",
    "az": "Azerbaijan",
    "bl": "Saint Bartelemey",
    "bs": "Bahamas",
    "bh": "Bahrain",
    "bd": "Bangladesh",
    "bb": "Barbados",
    "bq": "Bonaire, Saint Eustatius and Saba",
    "by": "Belarus",
    "be": "Belgium",
    "bz": "Belize",
    "bj": "Benin",
    "bm": "Bermuda",
    "bt": "Bhutan",
    "bo": "Bolivia",
    "ba": "Bosnia and Herzegowina",
    "bw": "Botswana",
    "bv": "Bouvet Island",
    "br": "Brazil",
    "io": "British Indian Ocean Territory",
    "bn": "Brunei Darussalam",
    "bg": "Bulgaria",
    "bf": "Burkina Faso",
    "bi": "Burundi",
    "kh": "Cambodia",
    "cm": "Cameroon",
    "ca": "Canada",
    "cv": "Cape Verde",
    "ky": "Cayman Islands",
    "cf": "Central African Republic",
    "td": "Chad",
    "cl": "Chile",
    "cn": "China",
    "cw": "Curacao",
    "cx": "Christmas Island",
    "cc": "Cocos (Keeling) Islands",
    "co": "Colombia",
    "km": "Comoros",
    "cg": "Congo",
    "cd": "Congo, The Democratic Republic of the",
    "ck": "Cook Islands",
    "cr": "Costa Rica",
    "ci": "Cote D'Ivoire",
    "hr": "Croatia",
    "cu": "Cuba",
    "cy": "Cyprus",
    "cz": "Czech Republic",
    "dk": "Denmark",
    "dj": "Djibouti",
    "dm": "Dominica",
    "do": "Dominican Republic",
    "tp": "East Timor",
    "ec": "Ecuador",
    "eg": "Egypt",
    "sv": "El Salvador",
    "gq": "Equatorial Guinea",
    "er": "Eritrea",
    "ee": "Estonia",
    "eu": "Europe",
    "et": "Ethiopia",
    "fk": "Falkland Islands (Malvinas)",
    "fo": "Faroe Islands",
    "fj": "Fiji",
    "fi": "Finland",
    "fr": "France",
    "gf": "French Guiana",
    "pf": "French Polynesia",
    "tf": "French Southern Territories",
    "ga": "Gabon",
    "gm": "Gambia",
    "ge": "Georgia",
    "de": "Germany",
    "gg": "Guernsey",
    "gh": "Ghana",
    "gi": "Gibraltar",
    "gr": "Greece",
    "gl": "Greenland",
    "gd": "Grenada",
    "gp": "Guadeloupe",
    "gu": "Guam",
    "gt": "Guatemala",
    "gn": "Guinea",
    "gw": "Guinea-Bissau",
    "gy": "Guyana",
    "ht": "Haiti",
    "hm": "Heard Island and Mcdonald Islands",
    "va": "Holy See (Vatican City State)",
    "hn": "Honduras",
    "hk": "Hong Kong",
    "hu": "Hungary",
    "is": "Iceland",
    "im": "Isle of Man",
    "in": "India",
    "id": "Indonesia",
    "ir": "Iran, Islamic Republic of",
    "iq": "Iraq",
    "ie": "Ireland",
    "il": "Israel",
    "it": "Italy",
    "je": "Jersey",
    "jm": "Jamaica",
    "jp": "Japan",
    "jo": "Jordan",
    "kz": "Kazakstan",
    "ke": "Kenya",
    "ki": "Kiribati",
    "kp": "Korea, Democratic People's Republic of",
    "kr": "Korea, Republic of",
    "kw": "Kuwait",
    "kg": "Kyrgyzstan",
    "la": "Lao People's Democratic Republic",
    "lv": "Latvia",
    "lb": "Lebanon",
    "ls": "Lesotho",
    "lr": "Liberia",
    "ly": "Libyan Arab Jamahiriya",
    "li": "Liechtenstein",
    "lt": "Lithuania",
    "lu": "Luxembourg",
    "me": "Montenegro",
    "mf": "Saint Martin",
    "mo": "Macau",
    "mk": "Macedonia, The Former Yugoslav Republic of",
    "mg": "Madagascar",
    "mw": "Malawi",
    "my": "Malaysia",
    "mv": "Maldives",
    "ml": "Mali",
    "mt": "Malta",
    "mh": "Marshall Islands",
    "mq": "Martinique",
    "mr": "Mauritania",
    "mu": "Mauritius",
    "yt": "Mayotte",
    "mx": "Mexico",
    "fm": "Micronesia, Federated States of",
    "md": "Moldova, Republic of",
    "mc": "Monaco",
    "mn": "Mongolia",
    "ms": "Montserrat",
    "ma": "Morocco",
    "mz": "Mozambique",
    "mm": "Myanmar",
    "na": "Namibia",
    "nr": "Nauru",
    "np": "Nepal",
    "nl": "Netherlands",
    "an": "Netherlands Antilles",
    "nc": "New Caledonia",
    "nz": "New Zealand",
    "ni": "Nicaragua",
    "ne": "Niger",
    "ng": "Nigeria",
    "nu": "Niue",
    "nf": "Norfolk Island",
    "mp": "Northern Mariana Islands",
    "no": "Norway",
    "om": "Oman",
    "pk": "Pakistan",
    "pw": "Palau",
    "ps": "Palestinian Territory, Occupied",
    "pa": "Panama",
    "pg": "Papua New Guinea",
    "py": "Paraguay",
    "pe": "Peru",
    "ph": "Philippines",
    "pn": "Pitcairn",
    "pl": "Poland",
    "pt": "Portugal",
    "pr": "Puerto Rico",
    "qa": "Qatar",
    "re": "Reunion",
    "ro": "Romania",
    "rs": "Serbia",
    "ru": "Russian Federation",
    "rw": "Rwanda",
    "sh": "Saint Helena",
    "kn": "Saint Kitts and Nevis",
    "lc": "Saint Lucia",
    "pm": "Saint Pierre and Miquelon",
    "vc": "Saint Vincent and the Grenadines",
    "ws": "Samoa",
    "sm": "San Marino",
    "st": "Sao Tome and Principe",
    "sa": "Saudi Arabia",
    "sn": "Senegal",
    "sc": "Seychelles",
    "sl": "Sierra Leone",
    "sg": "Singapore",
    "sk": "Slovakia",
    "si": "Slovenia",
    "sb": "Solomon Islands",
    "so": "Somalia",
    "ss": "South Sudan",
    "sx": "Sint Maarten",
    "za": "South Africa",
    "gs": "South Georgia and the South Sandwich Islands",
    "es": "Spain",
    "lk": "Sri Lanka",
    "sd": "Sudan",
    "sr": "Suriname",
    "sj": "Svalbard and Jan Mayen",
    "sz": "Swaziland",
    "se": "Sweden",
    "ch": "Switzerland",
    "sy": "Syrian Arab Republic",
    "tw": "Taiwan, Province of China",
    "tj": "Tajikistan",
    "tz": "Tanzania, United Republic of",
    "th": "Thailand",
    "tg": "Togo",
    "tk": "Tokelau",
    "tl": "Timor-Leste",
    "to": "Tonga",
    "tt": "Trinidad and Tobago",
    "tn": "Tunisia",
    "tr": "Turkey",
    "tm": "Turkmenistan",
    "tc": "Turks and Caicos Islands",
    "tv": "Tuvalu",
    "ug": "Uganda",
    "ua": "Ukraine",
    "ae": "United Arab Emirates",
    "gb": "United Kingdom",
    "us": "United States",
    "um": "United States Minor Outlying Islands",
    "uy": "Uruguay",
    "uz": "Uzbekistan",
    "vu": "Vanuatu",
    "ve": "Venezuela",
    "vn": "Viet Nam",
    "vg": "Virgin Islands, British",
    "vi": "Virgin Islands, U.S.",
    "wf": "Wallis and Futuna",
    "eh": "Western Sahara",
    "ye": "Yemen",
    "yu": "Yugoslavia",
    "zm": "Zambia",
    "zw": "Zimbabwe",
    }

class AnsiColors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    LIGHTBLUE = '\033[34m'
    YELLOW = '\033[33m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

def coloredConsoleLogging(fn):
    # add methods we need to the class
    def new(*args):
        levelno = args[1].levelno
        if(levelno>=50):
            color = AnsiColors.FAIL
        elif(levelno>=40):
            color = AnsiColors.FAIL
        elif(levelno>=30):
            color = AnsiColors.WARNING
        elif(levelno>=20):
            color = AnsiColors.LIGHTBLUE
        elif(levelno>=10):
            color = AnsiColors.OKGREEN
        else:
            color = AnsiColors.LIGHTBLUE
        args[1].msg = color + args[1].msg +  AnsiColors.ENDC # normal
        return fn(*args)
    return new

def usage():
    print('Usage: ')
    print(sys.argv[0] + ' \t\t\tBy default nothing will be blocked. Only a list of the ip addresses will be printed out.')
    print(sys.argv[0] + ' \t\t\tTo actually block the listed ip addresses add --block parameter.')
    print(sys.argv[0] + ' -h \t\t\tPrint this help message.')
    print(sys.argv[0] + ' --ips-by-query <query_name> --index <index_name> --min-count <min_hit_count>\tExecute elasticsearch query and block ip addresses. Optinal index name. Optional minimum term count.')
    print(sys.argv[0] + ' --ips-by-country <country_code>\tGet ip list for given country from http://http://www.ipdeny.com/ipblocks/data/countries/.')
    print(sys.argv[0] + ' --ips-by-url <url>\tGet ip list to block from given url')
    print(sys.argv[0] + ' --unblock <rule_name> \tWill delete the iptables block rule for the corresponding query.')
    print(sys.argv[0] + ' --unblock-all \t\tWill flush the complete INPUT chain thus unblocking all ip addresses.')
    print(sys.argv[0] + ' --list-queries \t\tList all available block queries.')
    print(sys.argv[0] + ' --list-countries \t\tList all available countries that can be blocked.')
    print(sys.argv[0] + ' --list-current-active \tList currently active blocking rules.')
    print(sys.argv[0] + ' --noresolve --list-blocked-ips <rule_name> List currently blocked ip addresses for given rule.')

def parseArgs():
    global index_name, query_name, min_count, country_code, ip_list_url, execute_blocking, execute_unblocking, resolve_ipaddress
    try:
        opts, args = getopt.getopt(sys.argv[1:], "h:", ["noresolve", "help", "index=", "ips-by-query=", "min-count=", "ips-by-country=", "ips-by-url=", "block", "unblock=", "unblock-all", "list-queries", "list-countries", "list-current-active", "list-blocked-ips="])
    except getopt.GetoptError:
        usage()
        sys.exit(255)
    if len(opts) == 0:
        usage()
        sys.exit(255)
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage()
            sys.exit()
        elif opt in ("--noresolve"):
            resolve_ipaddress = False
        elif opt in ("--dryrun"):
            execute_blocking = False
        elif opt in ("--index"):
            index_name = arg
        elif opt in ("--min-count"):
            min_count = int(arg)
        elif opt in ("--block"):
            execute_blocking = True
        elif opt in ("--ips-by-query"):
            query_name = arg
        elif opt in ("--ips-by-country"):
            country_code = arg
        elif opt in ("--ips-by-url"):
            ip_list_url = arg
        elif opt in ("--unblock"):
            rule_name = arg if arg else None
            active_rule_names = getCurrentActiveBlockRules()
            if not rule_name or rule_name not in active_rule_names:
                logger.error("Rule name %s unknown. List current active rules with:" % rule_name)
                logger.error(sys.argv[0] + ' --list-current-active \tList currently active blocking rules.')
                sys.exit(255)
            logger.info("Unblocking all ipaddresses from block rule %s." % rule_name)
            logger.info("Deleting iptables block rule for %s." % rule_name)
            deleteIptablesBlockRule(rule_name)
            logger.info("Deleting ipset for %s." % rule_name)
            destroyIpSetList(rule_name)
            sys.exit()
        elif opt in ("--unblock-all"):
            logger.info("Unblocking all ipaddresses.")
            unblockAll()
            sys.exit()
        elif opt in ("--list-queries"):
            logger.info("These are the available block queries:")
            listQueries()
            sys.exit()
        elif opt in ("--list-countries"):
            logger.info("These are the available countries for blocking:")
            listCountries()
            sys.exit()
        elif opt in ("--list-current-active"):
            logger.info("These are the currently active block rules:")
            for block_rule_name in getCurrentActiveBlockRules():
                logger.info("Active block rule: %s." % block_rule_name)
            sys.exit()
        elif opt in ("--list-blocked-ips"):
            query_name = arg
            logger.info("These are the currently blocked ip addresses for %s:" % query_name)
            listIpAddressesForActiveBlockRule(query_name)
            sys.exit()

def setupLogger():
    """
    Setup our logger.
    """
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logging.StreamHandler.emit = coloredConsoleLogging(logging.StreamHandler.emit)
    # Set loglevel for urllib3
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    # Set loglevel for elasticsearch
    logging.getLogger("elasticsearch").setLevel(logging.WARNING)
    return logging.getLogger()

def connect():
    """
    Connect to elasticsearch server.
    """
    es = False
    tries = 0
    while tries < 5 and not es:
        try:
            # Connect to es node and round-robin between them.
            logger.debug("Connecting to %s." % es_nodes)
            es = Elasticsearch(es_nodes)
        except:
            etype, evalue, etb = sys.exc_info()
            logger.warning("Connection to %s failed. Exception: %s, Error: %s." % (es_nodes,  etype, evalue))
            logger.warning("Waiting %s seconds before retring to connect." % ((4 + tries)))
            time.sleep(4 + tries)
            tries += 1
            continue
    if not es:
        logger.error("Connection to %s failed. Shutting down." % es_nodes)
        sys.exit(255)
    else:
        logger.debug("Connection to %s successful." % es_nodes)
    return es

def resolveCountryCode(country_code):
    """
    Resolve a country code, either by its iso code or its real name.
    """
    country_name = None
    if len(country_code) > 2:
        country_name = country_code
        country_code = next((cc for cc, country in countries.items() if country == country_code), None)
    if country_code not in countries:
        logger.error("Country code %s unknown. For a list of know codes execute:")
        logger.error(sys.argv[0] + ' --list-countries \tList all available countries that can be blocked.')
        sys.exit(255)
    if not country_name:
        country_name = countries[country_code]
    return [country_code, country_name]

def executeQuery(es_client, index_name, query):
    """
    Execute an elasticsearch query.
    """
    try:
        result = es_client.search(index=index_name, body=query)
    except:
        etype, evalue, etb = sys.exc_info()
        logger.error('The query %s failed. Exception: %s, Error: %s.' % (query, etype, evalue))
        sys.exit(255)
    return result

def getIpListFromElasticsearch(query_name, min_term_count=0):
    """
    Get a list of ipaddresses via an elasticsearch query.
    The query needs to return the ipaddresses as first aggregated field in result['aggregations'].
    The easiest way to build such a query is to use the kibana facet module and copy the used query via
    the info button of this module.
    """
    es = connect()
    result = executeQuery(es, index_name, elasticsearch_queries.queries[query_name])
    try:
        hits = result['aggregations'].itervalues().next()['buckets']
        hit_count = len(hits)
    except:
        logger.error("The search did not return a correct result. Return value: %s" % result)
        sys.exit(255)
    if hit_count == 0:
        logger.warning("The search did not yield any result. Nothing to block.")
        sys.exit()
    logger.info("Search yielded %d results. Filling block list <%s> with returned ip addresses." % (hit_count, query_name))
    ip_addresses = []
    for term in hits:
        if term['doc_count'] > min_term_count:
            ip_addresses.append(term['key'])
    return ip_addresses

def getIpListFromUrl(url):
    """
    Get the contents of a given url and parse out all contained ip addresses.
    """
    ip_list = []
    try:
        url_content = urllib2.urlopen(url).read()
    except:
        etype, evalue, etb = sys.exc_info()
        logger.error('Failed to retrieve ip list from %s. Exception: %s, Error: %s.' % (url, etype, evalue))
        sys.exit(255)
    regex_ip = re.compile('(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)', re.MULTILINE)
    matches = regex_ip.findall(url_content)
    for match in matches:
        ip_list.append(match)
    return ip_list

def createIpSetList(set_list_name):
    """
    Creates an ipset via <ipset create>
    If the ipset already exists it will be flushed.
    """
    result = subprocess.Popen("/usr/sbin/ipset list", shell=True, stdout=subprocess.PIPE).stdout.read()
    if "Name: %s" % set_list_name in result:
        # Flush existing set.
        #result = subprocess.Popen("/usr/sbin/ipset flush %s 2>&1" % set_list_name, shell=True, stdout=subprocess.PIPE).stdout.read()
        result = ""
    else:
        # Create new set.
        result = subprocess.Popen("/usr/sbin/ipset -N %s hash:net 2>&1" % set_list_name, shell=True, stdout=subprocess.PIPE).stdout.read()
    if result.strip() != "":
        logger.error("Could not create ipset %s. Error: %s." % (set_list_name, result))
        sys.exit(255)

def destroyIpSetList(set_list_name):
    """
    Removes an ipset by its name.
    """
    result = subprocess.Popen("/usr/sbin/ipset destroy %s 2>&1" % set_list_name, shell=True, stdout=subprocess.PIPE).stdout.read()
    if result.strip() != "":
        logger.error("Could not destroy ipset %s. Error: %s." % (set_list_name, result))
        sys.exit(255)

def addIpAddressesToIpSet(set_list_name, ip_addresses):
    """
    Add a list of ip addresses to an existing ipset.
    """
    for ip_address in ip_addresses:
        result = subprocess.Popen("/usr/sbin/ipset -A %s %s 2>&1" % (set_list_name, ip_address), shell=True, stdout=subprocess.PIPE).stdout.read()
        if result.strip() != "":
            logger.error("Could not add ip address %s to ipset %s. Error: %s." % (ip_address, set_list_name, result))

def addIptablesBlockRule(set_list_name):
    """
    Add an ipset to the iptables input chain with action drop.
    """
    result = subprocess.Popen("/sbin/iptables -L | grep 'match-set' | awk '{print $7}' 2>&1", shell=True, stdout=subprocess.PIPE).stdout.read()
    for line in result.strip().split('\n'):
        if line == set_list_name:
            return
    result = subprocess.Popen("/sbin/iptables -A INPUT -p tcp -m set --match-set %s src -j %s 2>&1" % (set_list_name, iptables_action), shell=True, stdout=subprocess.PIPE).stdout.read()
    if result.strip() != "":
        logger.error("Could not block ipset %s. Error: %s." % (set_list_name, result))

def deleteIptablesBlockRule(set_list_name):
    """
    To delete the iptables rule we need to delete by number since a delete by the rule name does not seem to work.
    """
    result = subprocess.Popen("/sbin/iptables -vnL --line-numbers | grep 'match-set %s' | awk '{print $1}'" % set_list_name, shell=True, stdout=subprocess.PIPE).stdout.read()
    try:
        rule_number = int(result)
    except:
        logger.error("Could not find iptables rule for %s. Error: %s" % (set_list_name, result))
        sys.exit(255)
    result = subprocess.Popen("/sbin/iptables -D INPUT %d 2>&1" % rule_number, shell=True, stdout=subprocess.PIPE).stdout.read()
    if result.strip() != "":
        logger.error("Could not delete iptables drop rule for %s. Error: %s." % (set_list_name, result))
        sys.exit(255)

def unblockAll():
    """
    Flush the iptables INPUT chain. That will effectively unblock all currently blocked ip addresses.
    """
    result = subprocess.Popen("/sbin/iptables -F INPUT 2>&1", shell=True, stdout=subprocess.PIPE).stdout.read()
    if result.strip() != "":
        logger.error("Could not flush INPUT chain. Error: %s." % (result))
    result = subprocess.Popen("/usr/sbin/ipset destroy 2>&1", shell=True, stdout=subprocess.PIPE).stdout.read()
    if result.strip() != "":
        logger.error("Could not destroy all ipsets. Error: %s." % (result))
        sys.exit(255)

def listQueries():
    """
    Print out a list of all configured elasticsearch queries available for selecting ip address to be blocked.
    """
    for query_name in elasticsearch_queries.queries.keys():
        logger.info("Query name: %s" % query_name)

def listCountries():
    try:
        country_list = urllib2.urlopen("http://www.ipdeny.com/ipblocks/data/countries/").read()
    except:
        etype, evalue, etb = sys.exc_info()
        logger.error('Failed to retrieve country list %s. Exception: %s, Error: %s.' % ("http://www.ipdeny.com/ipblocks/data/countries/", etype, evalue))
        sys.exit(255)
    regex_country_code = re.compile('(\w{1,2})\.zone')
    country_codes = {}
    for line in country_list.strip().split('\n'):
        matches = regex_country_code.findall(line)
        if not matches:
            continue
        country_code = matches[0]
        country_codes[country_code] = countries[country_code]
    for country_code in sorted(country_codes):
        logger.info("Country: %s (%s)" % (country_code, country_codes[country_code]))

def listBlockedIpAddresses(ip_addresses):
    """
    Print out a list of ip addresses with reverse lookup. Limit output to max 500.
    """
    for ip_address in ip_addresses[:500]:
        hostname = ip_address
        if resolve_ipaddress:
            try:
                hostname = str(resolver.query(reversename.from_address(ip_address), "PTR")[0])
            except:
                hostname = None
        logger.info('%s (%s)' % (ip_address, hostname))

def getCurrentActiveBlockRules():
    result = subprocess.Popen("/sbin/iptables -L | grep 'match-set' | awk '{print $7}' 2>&1", shell=True, stdout=subprocess.PIPE).stdout.read()
    block_rule_names = []
    for block_rule_name in result.strip().split('\n'):
        block_rule_names.append(block_rule_name)
    return block_rule_names

def listIpAddressesForActiveBlockRule(set_list_name):
    result = subprocess.Popen("/usr/sbin/ipset list %s 2>&1" % (set_list_name), shell=True, stdout=subprocess.PIPE).stdout.read()
    if 'The set with the given name does not exist' in result:
        logger.error("An ipset of the given name %s does not exist." % set_list_name)
        sys.exit(255)
    regex_ip = re.compile('(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)?)')
    blocked_ip_list = []
    for line in result.strip().split('\n'):
        matches = regex_ip.findall(line)
        if not matches:
            continue
        blocked_ip_list.append(matches[0])
    if blocked_ip_list:
        listBlockedIpAddresses(blocked_ip_list)

logger = setupLogger()

# Import queries file
sys.path.append(path_to_queries_file)
try:
    import elasticsearch_queries
except ImportError:
    logger.error('Could not import elasticsearch queries from %s. Please make sure %s/elasticearch_queries.py exists.' % (path_to_queries_file, path_to_queries_file))
    sys.exit(255)

parseArgs()

ip_addresses = None
if query_name:
    if query_name not in elasticsearch_queries.queries:
        logger.error('The search name "%s" is not defined in %s/elasticearch_queries.py.' % (sys.argv[2], path_to_queries_file))
        sys.exit(255)
    ip_addresses = getIpListFromElasticsearch(query_name, min_count)
    rule_name = query_name
elif country_code:
    country_code, country_name = resolveCountryCode(country_code)
    ip_list_url = "http://www.ipdeny.com/ipblocks/data/countries/%s.zone" % country_code
    ip_addresses = getIpListFromUrl(ip_list_url)
    rule_name = country_name
elif ip_list_url:
    ip_addresses = getIpListFromUrl(ip_list_url)
    rule_name = ip_list_url.rstrip('/').split('/')[-1]

if (query_name or country_code or ip_list_url) and not ip_addresses:
        logger.error('The search "%s" did not provide any ip addresses. Please check query.' %sys.argv[2] )
        sys.exit(255)

# Make list unique.
ip_addresses = list(set(ip_addresses))

# Filter out whitelisted ip addresses.
ip_addresses = [i for i in ip_addresses if i not in ip_whitelist]

if not execute_blocking:
    logger.info('The following %d ip addresses would be blocked: (List is limited to 500)' % len(ip_addresses))
    listBlockedIpAddresses(ip_addresses)
    sys.exit()

createIpSetList(rule_name)
hint = ""
if len(ip_addresses) > 1000:
    hint = " (might take a few seconds...)"
logger.info("Creating ipset %s with %d entries.%s" % (rule_name, len(ip_addresses), hint))
addIpAddressesToIpSet(rule_name, ip_addresses)
logger.info("Adding ipset %s to INPUT chain with %s action." % (rule_name, iptables_action))
addIptablesBlockRule(rule_name)
