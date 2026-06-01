"""models/ioc.py – IOC data model."""

from dataclasses import dataclass, field
from enum import Enum


class IOCType(str, Enum):
    IP         = "ip"
    DOMAIN     = "domain"
    URL        = "url"
    HASH_MD5   = "hash_md5"
    HASH_SHA1  = "hash_sha1"
    HASH_SHA256= "hash_sha256"


@dataclass
class IOC:
    value: str
    type:  IOCType
    tags:  list[str] = field(default_factory=list)
