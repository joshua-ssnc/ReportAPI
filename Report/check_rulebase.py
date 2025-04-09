import re
from sqlalchemy.orm import aliased
from sqlalchemy import Integer, String, cast, func, case, literal, and_, or_, not_, exists
import models, database
from datetime import datetime
import ipaddress
from models import SysLog, Rule, Service, Address, Analyze


class RuleTypes:
    def __init__(self):
        self.expired = set()
        self.permanent = set()
        self.redundant = set()
        self.shadow = set()
        self.unused = set()
        self.unused_objects = set()
        self.dst_excessiveopen = set()
        self.port_excessiveopen = set()
        self.knownportopen = set()
        self.virusportopen = set()
        self.mgmtportopen = set()
        self.src_anyopen = set()
        self.dst_anyopen = set()
        self.noevidence = set()
        self.compliancecheck = set()
        self.disabled = set()
        self.invalid = set()
        self.manual = set()


def is_valid_cidr(cidr):
    # Check if the input is a valid CIDR format
    cidr_pattern = r'^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$'
    return re.match(cidr_pattern, cidr) is not None

def is_valid_ip_range(ip_range):
    # Check if the input is a valid IP range format
    range_pattern = r'^([0-9]{1,3}\.){3}[0-9]{1,3}-([0-9]{1,3}\.){3}[0-9]{1,3}$'
    return re.match(range_pattern, ip_range) is not None

def is_valid_ip_list(ip_list):
    # Check if the input is a valid list of IP addresses
    ip_list_pattern = r'^([0-9]{1,3}\.){3}[0-9]{1,3}(,([0-9]{1,3}\.){3}[0-9]{1,3})*$'
    return re.match(ip_list_pattern, ip_list) is not None



def parseIPRange(range_str):
    # IP range in format 'start_ip-end_ip'

    start_ip_str, end_ip_str = range_str[3:].split('-')
    start_ip = ipaddress.IPv4Address(start_ip_str)
    end_ip = ipaddress.IPv4Address(end_ip_str)
    
    # Generate the IPs in the range
    return {ipaddress.IPv4Address(ip) for ip in range(int(start_ip), int(end_ip) + 1)}

def parseCIDR(cidr_str):
    # IP range in format '192.168.1.0/24'
    
    network = ipaddress.IPv4Network(cidr_str[3:], strict=False)
    return set(network.hosts()) | {network.network_address, network.broadcast_address}


def parseIPList(list_str):
    ip_list = list_str.split(',')
    return {ipaddress.IPv4Address(ip.strip()[3:]) for ip in ip_list}




def addressparseIPRange(range_str):
    # IP range in format 'start_ip-end_ip'

    start_ip_str, end_ip_str = range_str.split('-')
    start_ip = ipaddress.IPv4Address(start_ip_str)
    end_ip = ipaddress.IPv4Address(end_ip_str)
    
    # Generate the IPs in the range
    return {ipaddress.IPv4Address(ip) for ip in range(int(start_ip), int(end_ip) + 1)}

def addressparseCIDR(cidr_str):
    # IP range in format '192.168.1.0/24'
    
    network = ipaddress.IPv4Network(cidr_str, strict=False)
    return set(network.hosts()) | {network.network_address, network.broadcast_address}


def addressparseIPList(list_str):
    ip_list = list_str.split(',')
    return {ipaddress.IPv4Address(ip.strip()) for ip in ip_list}





def parseAddressMembers(members):
    addressIPs = set()

    for member in members:
        if is_valid_ip_list(member): # It's a list of IPs
            addressIPs.update(addressparseIPList(member))
        elif is_valid_ip_range(member):  # It's a range of IPs
            addressIPs.update(addressparseIPRange(member))
        elif is_valid_cidr(member):  # It's a CIDR
            addressIPs.update(addressparseCIDR(member))
        else:  # It's a single IP ro domain 
            addressIPs.add(member)
        
    return addressIPs
            



def parseRuleIPs(rules):
    ruleIPs = []

    for rule in rules:
        source = rule.source
        destination = rule.destination

        if not source.startswith("IP_"):
            sourceIPs = {source}  # This can be handled as a wildcard match, adjust as necessary
        elif '-' in source:  # It's a range (starts with 'IP_')
            sourceIPs = parseIPRange(source)
        elif '/' in source:  # It's a CIDR (starts with 'IP_')
            sourceIPs = parseCIDR(source)
        else:  # It's a list of IPs (starts with 'IP_')
            sourceIPs = parseIPList(source)

        if not destination.startswith("IP_"):
            dstIPs = {destination}  # This can be handled as a wildcard match, adjust as necessary
        elif '-' in destination:  # It's a range (starts with 'IP_')
            dstIPs = parseIPRange(destination)
        elif '/' in destination:  # It's a CIDR (starts with 'IP_')
            dstIPs = parseCIDR(destination)
        else:  # It's a list of IPs (starts with 'IP_')
            dstIPs = parseIPList(destination)
        
        ruleIPs.append({"id": rule.id, "source": sourceIPs, "destination": dstIPs, "service": rule.service})
    
    return ruleIPs



def analyze(rules, analyses, complianceObjects, fw_id, db):
    ruleIPs = parseRuleIPs(rules)

    types = RuleTypes()

    analyzeQuery = db.query(Analyze).filter(Analyze.fw_id == fw_id)

    for rule in rules:
        # THIS IS BETTER FOR SMALLER DATASETS
        # ruleAnalysesPorts = list(filter(lambda r : r.rulebase_id == rule.id and r.ctype == 0, analyses))

        # ruleAnalysesSource = list(filter(lambda r : r.rulebase_id == rule.id and r.ctype == 2, analyses))
        # ruleAnalysesDest = list(filter(lambda r : r.rulebase_id == rule.id and r.ctype == 3, analyses))

        # OPTIMIZING FOR LARGER DATASETS
        analyzeQuery = db.query(Analyze).filter(Analyze.fw_id == fw_id)

        ruleAnalysesPorts = analyzeQuery.filter(Analyze.rulebase_id == rule.id and Analyze.ctype == 0).all()
        ruleAnalysesSource = analyzeQuery.filter(Analyze.rulebase_id == rule.id and Analyze.ctype == 2).all()
        ruleAnalysesDest = analyzeQuery.filter(Analyze.rulebase_id == rule.id and Analyze.ctype == 3).all()

        ruleSources = sorted([(a.start_object, a.end_object) for a in ruleAnalysesSource])
        ruleDests = sorted([(a.start_object, a.end_object) for a in ruleAnalysesDest])

        # EXPIRED RULE
        if check_expired(rule):
            types.expired.add(rule.id) 

        # PERMANENT
        if check_permanent(rule):
            types.permanent.add(rule.id) 

        # UNUSED OBJECTS
        if check_unused_objects(db, fw_id, rule.id):
            types.unused_objects.add(rule.id)

        # DST_EXCESSIVEOPEN
        if check_dst_excessiveopen(rule):
            types.dst_excessiveopen.add(rule.id) 

        # PORT_EXCESSIVEOPEN
        if check_port_excessiveopen(rule, ruleAnalysesPorts):
            types.port_excessiveopen.add(rule.id) 
        
        # KNOWNPORTOPEN
        if check_portopen(rule, list(filter(lambda a : a.type == "wn", complianceObjects)), ruleAnalysesPorts):
            types.knownportopen.add(rule.id) 
        
        # VIRUSPORTOPEN
        if check_portopen(rule, list(filter(lambda a : a.type == "vi", complianceObjects)), ruleAnalysesPorts):
            types.virusportopen.add(rule.id) 
        
        # MGMTPORTOPEN 
        if check_portopen(rule, list(filter(lambda a : a.type == "mn", complianceObjects)), ruleAnalysesPorts):
            types.mgmtportopen.add(rule.id) 
        
        # SRC_ANYOPEN 
        if check_src_anyopen(rule, ruleSources):
            types.src_anyopen.add(rule.id) 
        
        # DST_ANYOPEN 
        if check_dst_anyopen(rule, ruleDests):
            types.dst_anyopen.add(rule.id) 
        
        # NOEVIDENCE 
        if check_noevidence(rule):
            types.noevidence.add(rule.id) 
        
        # COMPLIANCECHECK 
        if check_compliancecheck(rule):
            types.compliancecheck.add(rule.id) 
        
        # DISABLED 
        if check_disabled(rule):
            types.disabled.add(rule.id) 

        # INVALID 
        if check_invalid(rule):
            types.invalid.add(rule.id) 

        # MANUAL 
        if check_manual(rule):
            types.manual.add(rule.id) 

    # UNUSED RULES AND OBJECTS
    types.unused.update(retrieve_unused(db, fw_id))

    types.unused_objects.update(retrieve_unused_objects(db, fw_id))


    seenRules = {}
    for idx, rule in enumerate(ruleIPs):
        # REDUNDANT
        check_redundant(rule, seenRules, types.redundant)

        # SHADOW
        if check_shadow(ruleIPs, idx):
            types.shadow.add(rule["id"]) 
    

    return types



def retrieve_unused_objects(db, fw_id):
    # Query to transform the SysLog "service" column into separate protocol and port columns 
    syslogs = db.query(
        SysLog.id,
        SysLog.policyid,
        SysLog.srcip,
        SysLog.dstip,
        case(
            (SysLog.service.like('tcp/%') | SysLog.service.like('udp/%'), func.substr(SysLog.service, 1, func.position(literal('/').op('IN')(SysLog.service)) - 1)),  # Extract protocol
            else_=Service.protocol
        ).label('protocol'),
        
        case(
            (SysLog.service.like('tcp/%') | SysLog.service.like('udp/%'), cast(func.substr(SysLog.service, func.position(literal('/').op('IN')(SysLog.service)) + 1, 5), Integer)),  # Extract port
            else_=SysLog.dstport
        ).label('port'),
    ).outerjoin(
        Service, SysLog.service == Service.name  # Outer join if the service name matches a service
    ).subquery()

    syslog_alias = aliased(syslogs, name='syslog_alias')

    existenceSubquery = db.query(syslog_alias.c.policyid).filter(
        and_(
            cast(Analyze.rulebase_id, String) == syslog_alias.c.policyid,
            or_(
                # For rules that deal with ports/protocols (ctype 0 and 1)
                and_(

                    Analyze.ctype.in_([0, 1]),  # Type 0 or 1: ports and protocols
                    or_(
                        and_(
                            Analyze.ctype == 0,
                            syslog_alias.c.protocol == 'tcp'
                        ),
                        and_(
                            Analyze.ctype == 1,
                            syslog_alias.c.protocol == 'udp'
                        )
                    ),
                    # checks if syslog port is in range
                    syslog_alias.c.port.between(Analyze.start_object, Analyze.end_object)

                ),
                # For rules that deal with source IP addresses (ctype 2)
                and_(
                    Analyze.ctype == 2,  # Type 2: Source IP address
                    syslog_alias.c.srcip.between(Analyze.start_object, Analyze.end_object)
                ),
                # For rules that deal with destination IP addresses (ctype 3)
                and_(
                    Analyze.ctype == 3,  # Type 3: Destination IP address
                    # Destination IP range match (ctype 3)
                    syslog_alias.c.dstip.between(Analyze.start_object, Analyze.end_object),
                )
            )
        )
    ).exists()


    analysisQuery = db.query(Analyze.rulebase_id).outerjoin(syslog_alias, 
        and_(
            cast(Analyze.rulebase_id, String) == syslog_alias.c.policyid,
            or_(
                # For rules that deal with ports/protocols (ctype 0 and 1)
                and_(

                    Analyze.ctype.in_([0, 1]),  # Type 0 or 1: ports and protocols
                    or_(
                        and_(
                            Analyze.ctype == 0,
                            syslog_alias.c.protocol == 'tcp'
                        ),
                        and_(
                            Analyze.ctype == 1,
                            syslog_alias.c.protocol == 'udp'
                        )
                    ),
                    # Checks if syslog port is in range
                    syslog_alias.c.port.between(Analyze.start_object, Analyze.end_object)
    
                ),
                # For rules that deal with source IP addresses (ctype 2)
                and_(
                    Analyze.ctype == 2,  # Type 2: Source IP address
                    syslog_alias.c.srcip.between(Analyze.start_object, Analyze.end_object)
                ),
                # For rules that deal with destination IP addresses (ctype 3)
                and_(
                    Analyze.ctype == 3,  # Type 3: Destination IP address
                    syslog_alias.c.dstip.between(Analyze.start_object, Analyze.end_object),
                )
            )
        )
    ).filter(and_(Analyze.fw_id == fw_id, syslog_alias.c.id == None)).distinct()

    # Uses exists() for short circuit evaluation
    optimizedAnalysis = db.query(Analyze.rulebase_id).filter(
        and_(
            Analyze.fw_id == fw_id,
            ~existenceSubquery
        )
    ).distinct().all()

    return [analysis.rulebase_id for analysis in optimizedAnalysis]





# TODO: check rivions=0 rule for all of these

def check_expired(rule):
    if rule.expire and rule.expire < datetime.now():
        return True

    return False


def check_permanent(rule): 
    permanentDate = datetime(9999, 1, 1, 0, 0)
    if rule.expire and rule.expire >= permanentDate:
        return True

    return False


def check_redundant(rule, seenRules, dupRulesIds):
    ruleTuple = (tuple(sorted(rule["source"])), tuple(sorted(rule["destination"])), rule["service"])
    
    if ruleTuple in seenRules:
        dupRulesIds.add(seenRules[ruleTuple])
        dupRulesIds.add(rule["id"])
    else:
        seenRules[ruleTuple] = rule["id"]





def check_shadow(ruleIPs, idx):
    rule = ruleIPs[idx]
    ruleService = rule["service"]
    ruleSource = rule["source"]
    ruleDestination = rule["destination"]
    for i in range(len(ruleIPs)):
        if i == idx:
            continue

        existingRule = ruleIPs[i]
        existingService = existingRule["service"]
        existingSource = existingRule["source"]
        existingDestination = existingRule["destination"]
    
        if ruleService == existingService and ruleSource.issubset(existingSource) and ruleDestination.issubset(existingDestination):
            return True

    return False


def retrieve_unused(db, fw_id):
    unusedRulesQuery = db.query(Rule.id).outerjoin(SysLog, cast(Rule.id, String) == SysLog.policyid).filter(Rule.fw_id == fw_id).filter(SysLog.id == None).all()
    return [unusedRule.id for unusedRule in unusedRulesQuery]



def check_unused_objects(db, fw_id, rule_id):
    portAnalysis = db.query(Analyze).filter(Analyze.fw_id == fw_id)


def check_dst_excessiveopen(rule):
    if rule.service == "any":
            return True

    return False


def check_port_excessiveopen(rule, analyses):
    # Check how many ports is too many
    # in the example Mr. Lee provided me, that number was 100
    
    if rule.service == "any":
        return True

    counter = 0
    for analysis in analyses:
        counter += (analysis.end_object - analysis.start_object)
        if counter > 100:
            return True

    return False


def check_portopen(rule, complianceObjects, analyses):
    if complianceObjects and rule.service == "any":
        return True

    for obj in complianceObjects:
        start, end = obj.start_object, obj.end_object

        for analysis in analyses:
            aStart, aEnd = analysis.start_object, analysis.end_object

            if start <= aEnd and aStart <= end:
                return True
            
    return False


def check_src_anyopen(rule, sources):
    if rule.source == "any":
            return True
    
    # sources is a sorted list of (startIP, endIP) from argos_analysis
    # where ctype == 2
    currStart = 0

    for (start, end) in sources:
        # If the current interval starts after the current covered range, there's a gap
        if start > currStart:
            return False
        
        # Extend the current covered range to the end of this interval
        currStart = max(currStart, end)

    return True if currStart >= 4294836225 else 0
    

def check_dst_anyopen(rule, dests):
    if rule.destination == "any":
            return True
    
    # dests is a sorted list of (startIP, endIP) from argos_analysis
    # where ctype == 3
    currStart = 0

    for (start, end) in dests:
        # If the current interval starts after the current covered range, there's a gap
        if start > currStart:
            return False
        
        # Extend the current covered range to the end of this interval
        currStart = max(currStart, end)

    return True if currStart >= 4294836225 else 0


def check_noevidence(rule):
    if not rule.comment.strip():
        return True

    return False


def check_compliancecheck(rule):
    # need to clarify this and how a rule can be identified as a compliance rule
    # or not

    return False


def check_disabled(rule):
    # check possible other conditions for what constitutes a disabled rule

    if not rule.apply_id:
        return True

    return False


def check_invalid(rule):
    # need to clarify what constitutes a invalid rule

    return False


def check_manual(rule):
    if rule.rivision == -1:
        return True

    return False

