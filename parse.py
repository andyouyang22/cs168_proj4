def rules(filename):
	"""
	Create an array of rules from the rules file specified in the firewall config.
	"""
	rules = []
	rule_file = open(filename)
	for rule in rule_file:
		rule = rule.split()
		if len(rule) < 1:
			continue
		for i in range(len(rule)):
			rule[i] = rule[i].lower()
		if rule[0] == '%':
			continue
		if rule[1] == "tcp" or rule[1] == "udp" or rule[1] == "icmp":
			new_rule = {
				'verdict'  : rule[0],
				'protocol' : rule[1],
				'ext_ip'   : rule[2],
				'ext_port' : rule[3],
			}
		elif rule[1] == "dns":
			new_rule = {
				'verdict'  : rule[0],
				'protocol' : 'dns',
				'domain_name' : rule[2],
			}
		else:
			# probably just a line of text, do nothing
			continue
		print new_rule
		rules.append(new_rule)
	return rules

def geos(filename):
	"""
	Create an array of geographical IP mappings from the GeoIP file specified.
	"""
	geos = []
	geo_file = open(filename)
	for geo_line in geo_file:
		geo_line = geo_line.split()
		for i in range(len(geo_line)):
			geo_line[i] = geo_line[i].lower()
		new_geo = {
			'start_ip'     : geo_line[0],
			'end_ip'       : geo_line[1],
			'country_code' : geo_line[2],
		}
		geos.append(new_geo)
	return geos
