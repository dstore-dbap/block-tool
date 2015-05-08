block-tool
===========

Introduction
''''''''''''

| A simple block tool to easily block selected ip addresses via different sources.
| At the moment, elasticsearch, http://www.ipdeny.com/ipblocks/data/countries/ and general urls are supported as sources.
| The selected ip addresses will be added to an ipset (which is a requirement for this tool to work) and an iptables rule will be craeted to drop these addresses.

.. parsed-literal::

  Usage:
  ./block_tool.py 			By default nothing will be blocked. Only a list of the ip addresses will be printed out.
  ./block_tool.py 			To actually block the listed ip addresses add --block parameter.
  ./block_tool.py -h 			Print this help message.
  ./block_tool.py --ips-by-query <query_name> --index <index_name>	Execute elasticsearch query and block ip addresses. Optinal index name.
  ./block_tool.py --ips-by-country <country_code>	Get ip list for given country from http://http://www.ipdeny.com/ipblocks/data/countries/.
  ./block_tool.py --ips-by-url <url>	Get ip list to block from given url
  ./block_tool.py --unblock <rule_name> 	Will delete the iptables block rule for the corresponing query.
  ./block_tool.py --unblock-all 		Will flush the complete INPUT chain thus unblocking all ip addresses.
  ./block_tool.py --list-queries 		List all available block queries.
  ./block_tool.py --list-countries 		List all available countries that can be blocked.
  ./block_tool.py --list-current-active 	List currently active blocking rules.
  ./block_tool.py --noresolve --list-blocked-ips <rule_name> List currently blocked ip addresses for given rule.

ips-by-query
''''''''''''

| Block ip addresses based on the result of an elasticsearch query.
| The query needs to return the ipaddresses as facetted fields in result['facets']['terms']['terms'].
| The easiest way to build such a query is to use the kibana facet module and copy the used query via
| the info button of this module.
| The query source need to be stored in the elasticsearch_queries.queries dictionary.

ips-by-country
''''''''''''''
| A list of ip addresses for the selected country will be retrieved from http://www.ipdeny.com/ipblocks/data/countries/

ips-by-url
''''''''''
| The contents of the passed url will be scanned for ip address patterns. Found ip addresses will be added to the block list.
| This can be useful to block e.g. tor exit nodes via:

.. parsed-literal::

  ./block-tool.py ips-by-url https://torstatus.blutmagie.de/

| As always be sure to not overload urls that do not belong to you.