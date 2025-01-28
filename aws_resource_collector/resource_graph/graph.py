from dataclasses import dataclass, field, asdict
from enum import StrEnum, auto
from typing import List, Dict, Any, Tuple

from aws_resource_collector.utils.dataclass import dataclass_from_dict


class ResourceType(StrEnum):
    API_GATEWAY = auto()
    CLOUD_WATCH = auto()
    DYNAMODB = auto()
    EC2 = auto()
    ECR = auto()
    ECS = auto()
    EFS = auto()
    EKS = auto()
    ELASTICACHE = auto()
    EMR = auto()
    EVENT_BRIDGE = auto()
    GLUE = auto()
    IAM = auto()
    INTERNET_GATEWAY = auto()
    KINESIS = auto()
    KMS = auto()
    LAMBDA = auto()
    NAT_GATEWAY = auto()
    OPEN_SEARCH = auto()
    RDS = auto()
    REDSHIFT = auto()
    ROUTE53 = auto()
    S3 = auto()
    SECRETS_MANAGER = auto()
    SECURITY_GROUP = auto()
    SNS = auto()
    SQS = auto()
    STEP_FUNCTIONS = auto()
    SUBNET = auto()
    TRANSFER_FAMILY = auto()


@dataclass
class BasicResource:
    id: str
    type: ResourceType
    name: str
    depends_on: list[str] = field(default_factory=list)

@dataclass
class Workspace:
    name: str
    env: str
    resources: List[BasicResource] = field(default_factory=list)

@dataclass
class Resource(BasicResource):
    env: str = "Dev"
    app_id: str = "Unknown"

def group_by(items: List[Resource]):
    groups = group_by(items, lambda x: (x.app_id, x.env))
    return [map_group(key, group) for key, group in groups]

def map_group(key: Tuple[str, str], resources: List[Resource]) -> Workspace:
    basic_resources = [dataclass_from_dict(BasicResource, **asdict(resource)) for resource in resources]
    return Workspace(name=key[0], env=key[1], resources=basic_resources)
