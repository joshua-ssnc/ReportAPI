
from sqlalchemy import Column, Integer, String, DateTime, CheckConstraint, JSON, func
from database import Base

class Firewall(Base):
    __tablename__ = "argos_firewall_list"

    id = Column(Integer, primary_key=True)
    fw_name = Column(String, index=True)
    name = Column(String, unique=True, index=True)
    ipaddr = Column(String, unique=True)
    admin = Column(String)
    admin_pw = Column(String)
    restapi_user = Column(String)
    restapi_pw = Column(String)
    token = Column(String)

    # rules = relationship("Rule", back-populates)


class Rule(Base):
    __tablename__ = "argos_rulebase"

    id = Column(Integer, primary_key=True)
    fw_id = Column(Integer, index=True)
    name = Column(String, unique=True, index=True)
    rivision = Column(Integer, CheckConstraint('rivision == -1 or rivision == 0', name='check_rivision'))
    from_ip = Column(String, index=True)
    to_ip = Column(String, index=True)
    source = Column(String, index=True)
    destination = Column(String, index=True)
    source_user = Column(String, nullable=True)
    application = Column(String, nullable=True)
    action = Column(String, CheckConstraint("action IN ('allow', 'deny')", name='check_action'))
    comment = Column(String, nullable=True)
    seq = Column(Integer, nullable=True)
    schedule = Column(DateTime, nullable=True)
    expire = Column(String, nullable=True)
    apply_id = Column(String, nullable=True)
    deleted = Column(Integer)
    sync = Column(Integer)
    ts = Column(DateTime)
    service = Column(String)
    

class Analyze(Base):
    __tablename__ = "argos_analyze"

    id = Column(Integer, primary_key=True)
    fw_id = Column(Integer, index=True)
    rivision = Column(Integer, CheckConstraint('rivision == -1 or rivision == 0', name='check_rivision'))
    rulebase_id = Column(Integer, index=True)
    ctype = Column(Integer, CheckConstraint('ctype == 1 or ctype == 0 ctype == 2 or ctype == 3', name='check_ctype'))
    rulebase_id = Column(Integer)
    start_object = Column(Integer, CheckConstraint('start_object >= 0 and start_object <= 4294836225', name='check_start_object'))
    end_object = Column(Integer, CheckConstraint('end_object >= 0 and end_object <= 4294836225', name='check_end_object'))
    cobject = Column(String, nullable=True)
    expire = Column(DateTime, nullable=True)
    sync = Column(Integer)
    action = Column(Integer, CheckConstraint('action == -1 or action == 0', name='check_action'))


class ComplianceObject(Base):
    __tablename__ = "argos_compliance_object"

    id = Column(Integer, primary_key=True)
    type = Column(String, index=True)
    name = Column(String, unique=True)
    start_object = Column(Integer, CheckConstraint('start_object >= 0 and start_object <= 4294836225', name='check_start_object'), nullable=True)
    end_object = Column(Integer, CheckConstraint('end_object >= 0 and end_object <= 4294836225', name='check_end_object'), nullable=True)
    object = Column(String, nullable=True)
    category = Column(String, nullable=True)
    comment = Column(String, nullable=True)
    ts = Column(DateTime)

class Service(Base):
    __tablename__ = "argos_service"

    id = Column(Integer, primary_key=True)
    fw_id = Column(Integer, index=True)
    name = Column(String, index=True, unique=True)
    rivision = Column(Integer, CheckConstraint('rivision == -1 or rivision == 0', name='check_rivision'), nullable=True)
    deleted = Column(Integer, nullable=True)
    sync = Column(Integer, nullable=True)
    ts = Column(DateTime, nullable=True)
    protocol = Column(String, nullable=True, index=True)
    member = Column(String, nullable=True, index=True)


class Address(Base):
    __tablename__ = "argos_address"

    id = Column(Integer, primary_key=True)
    fw_id = Column(Integer, index=True)
    name = Column(String, unique=True)
    rivision = Column(Integer, CheckConstraint('rivision == -1 or rivision == 0', name='check_rivision'), nullable=True)
    member = Column(String, nullable=True)
    deleted = Column(Integer, nullable=True)
    sync = Column(Integer, nullable=True)
    ts = Column(DateTime, nullable=True)


class SysLog(Base):
    __tablename__ = "argos_syslog"

    id = Column(Integer, primary_key=True)
    seq = Column(Integer)
    devid = Column(String)
    eventtime = Column(DateTime)
    logid = Column(String)
    type = Column(String)
    subtype = Column(String)
    level = Column(String)
    srcip = Column(String, index=True)
    srcport = Column(Integer)
    dstip = Column(String, index=True)
    dstport = Column(Integer)
    dstintf = Column(String)
    policyid = Column(String, index=True)
    policytype = Column(String, nullable=True)
    sessionid = Column(String)
    service = Column(String, index=True)
    duration = Column(Integer)
    sentbyte = Column(Integer)
    rcvdbyte = Column(Integer)
    srccountry = Column(String)
    dstcountry = Column(String)
    action = Column(String)
    app = Column(String, nullable=True)
    hostname = Column(String, nullable=True)
    apprisk = Column(String, nullable=True)
    times = Column(Integer)

class Report(Base):
    __tablename__ = "ag_report"

    id = Column(Integer, primary_key=True)
    fw_id = Column(Integer, index=True)
    update_ts = Column(DateTime, server_default=func.now())
    jsondata = Column(JSON)

class Weights(Base):
    __tablename__ = "ag_weights"

    id = Column(Integer, primary_key=True)
    expired = Column(Integer, default=0, server_default="0")
    permanent = Column(Integer, default=0, server_default="0")
    redundant = Column(Integer, default=0, server_default="0")
    shadow = Column(Integer, default=0, server_default="0")
    partial_shadow = Column(Integer, default=0, server_default="0")
    unused = Column(Integer, default=0, server_default="0")
    unused_objects = Column(Integer, default=0, server_default="0")
    src_excessiveopen = Column(Integer, default=0, server_default="0")
    dst_excessiveopen = Column(Integer, default=0, server_default="0")
    port_excessiveopen = Column(Integer, default=0, server_default="0")
    knownportopen = Column(Integer, default=0, server_default="0")
    virusportopen = Column(Integer, default=0, server_default="0")
    mgmtportopen = Column(Integer, default=0, server_default="0")
    src_anyopen = Column(Integer, default=0, server_default="0")
    dst_anyopen = Column(Integer, default=0, server_default="0")
    port_anyopen = Column(Integer, default=0, server_default="0")
    greater30days = Column(Integer, default=0, server_default="0")
    noevidence = Column(Integer, default=0, server_default="0")
    compliancecheck = Column(Integer, default=0, server_default="0")
    deny = Column(Integer, default=0, server_default="0")
    checkpolicyreg = Column(Integer, default=0, server_default="0")
    checkcomposition = Column(Integer, default=0, server_default="0")
    disabled = Column(Integer, default=0, server_default="0")
    invalid = Column(Integer, default=0, server_default="0")
    manual = Column(Integer, default=0, server_default="0")
    unregistered = Column(Integer, default=0, server_default="0")
    nozone = Column(Integer, default=0, server_default="0")