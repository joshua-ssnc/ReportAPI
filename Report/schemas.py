
from typing import Optional, Literal, Dict
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum

class Firewall(BaseModel):
    id: int
    fw_name: str
    name: str
    ipaddr: str
    admin: str
    admin_pw: str
    restapi_user: Optional[str] = None
    restapi_pw: Optional[str] = None
    token: Optional[str] = None

    # class Config:
    #     orm_mode = True


class Rule(BaseModel):
    id: int
    fw_id: int
    name: str
    rivision: int = Field(gte=-1, lt=1)
    from_ip: str
    to_ip: str
    source: str
    destination: str
    source_user: Optional[str] = None
    application: Optional[str] = None
    action: Literal['allow', 'deny']
    comment: Optional[str] = None
    seq: Optional[int] = -1
    schedule: datetime
    expire: datetime
    apply_id: Optional[str] = None
    deleted: int
    sync: int
    ts: datetime
    service: str

class RuleType(Enum):
    EXPIRED = 1
    PERMANENT = 2
    REDUNDANT = 3
    SHADOW = 4
    UNUSED = 5
    DST_EXCESSIVEOPEN = 6
    PORT_EXCESSIVEOPEN = 7
    KNOWNPORTOPEN = 8
    VIRUSPORTOPEN = 9
    MGMTPORTOPEN = 10
    SRC_ANYOPEN = 11
    DST_ANYOPEN = 12
    NOEVIDENCE = 13
    COMPLIANCECHECK = 14
    DISABLED = 15
    INVALID = 16
    MANUAL = 17


# defines structure of rule data for each firewall
class RuleAnalysis(BaseModel):
    fw_id: int
    # rules_count is a dictionary that stores counts of rules by type
    rules_count: Dict[RuleType, int]

    class Config:
        use_enum_values = True


class FirewallAnalysis(BaseModel):
    firewalls: Dict[int, Dict[RuleType, int]]

    class Config:
        use_enum_values = True