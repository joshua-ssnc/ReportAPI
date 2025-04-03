
from sqlalchemy import Column, Integer, String, DateTime, CheckConstraint
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
    expire = Column(DateTime, nullable=True)
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
    srcip = Column(Integer)
    srcport = Column(Integer)
    dstip = Column(Integer)
    dstport = Column(Integer)
    dstintf = Column(String)
    policyid = Column(String, index=True)
    policytype = Column(String, nullable=True)
    sessionid = Column(String)
    service = Column(String)
    duration = Column(Integer)
    sentbyte = Column(Integer)
    rcvdbyte = Column(Integer)
    srccountry = Column(String)
    dstcountry = Column(String)
    action = Column(String)
    app = Column(String, nullable=True)
    hostname = Column(String, nullable=True)
    apprisk = Column(String, nullable=True)
