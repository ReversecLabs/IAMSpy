"""
Classes representing IAM documents
"""
from __future__ import annotations
from dataclasses import asdict
from pydantic import Field, field_validator, model_validator
from pydantic.dataclasses import dataclass
from datetime import datetime, date
from typing import Optional, List, Dict, Union, Any
from enum import Enum
import logging


logger = logging.getLogger("iamspy.iam")


def json_serial(obj):
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    elif isinstance(obj, Effects):
        return obj.value
    else:
        raise TypeError("Unserializable object {} of type {}".format(obj, type(obj)))


class Effects(Enum):
    ALLOW = "Allow"
    DENY = "Deny"


@dataclass
class Statements:
    Sid: Optional[str] = None
    Effect: Effects = Field(Effects.DENY)
    Principal: Optional[Dict[str, List[str]]] = None
    NotPrincipal: Optional[Dict[str, List[str]]] = None
    Action: Optional[Union[str, List[str]]] = None
    NotAction: Optional[Union[str, List[str]]] = None
    Resource: Optional[Union[str, List[str]]] = None
    NotResource: Optional[Union[str, List[str]]] = None
    Condition: Optional[Dict[str, Dict[str, Union[str, List[str]]]]] = None

    @field_validator("Principal", mode="before")
    def principal_is_list(cls, v):
        if not v:
            return v
        if isinstance(v, str):
            v = {"AWS": v}
        for key, value in v.items():
            if isinstance(value, str):
                v[key] = [value]
        return v

    @field_validator("NotPrincipal", mode="before")
    def notprincipal_is_list(cls, v):
        if not v:
            return v
        if isinstance(v, str):
            v = {"AWS": v}
        for key, value in v.items():
            if isinstance(value, str):
                v[key] = [value]
        return v

    @model_validator(mode="after")
    def at_least_action_or_not_action(self) -> Self:
        if not self.Action and not self.NotAction:
            raise ValueError("At least one of Action and NotAction must be specified")
        return self


@dataclass
class Document:
    Version: Optional[str] = "2008-10-17"
    Id: Optional[str] = None
    Statement: List[Statements] = Field(default_factory=list)

    @field_validator("Statement", mode="before")
    def make_sure_statements_is_list(cls, v):
        if not isinstance(v, list):
            return [v]
        return v


@dataclass
class Policy:
    PolicyName: str
    PolicyDocument: Document


@dataclass
class ManagedPolicy:
    PolicyName: str
    PolicyArn: str


@dataclass
class PermissionBoundary:
    PermissionsBoundaryType: str = Field(..., pattern="^Policy$")
    PermissionsBoundaryArn: str = Field(...)


@dataclass
class Tag:
    Key: str
    Value: str


@dataclass
class AccessKey:
    UserName: str
    AccessKeyId: str
    Status: str
    CreateDate: datetime


@dataclass
class LoginProfile:
    UserName: str
    CreateDate: datetime
    PasswordResetRequired: bool


@dataclass
class UserDetail:
    Path: str
    UserName: str
    UserId: str
    Arn: str
    CreateDate: datetime
    UserPolicyList: List[Policy] = Field(default_factory=list)
    PasswordLastUsed: Optional[datetime] = None
    GroupList: List[str] = Field(default_factory=list)
    AttachedManagedPolicies: List[ManagedPolicy] = Field(default_factory=list)
    LoginProfile: Optional[LoginProfile] = None
    AccessKeys: Optional[List[AccessKey]] = None
    PermissionsBoundary: Optional[PermissionBoundary] = None
    Tags: List[Tag] = Field(default_factory=list)


@dataclass
class GroupDetail:
    Path: str
    GroupName: str
    GroupId: str
    Arn: str
    CreateDate: datetime
    GroupPolicyList: List[Policy]
    AttachedManagedPolicies: List[ManagedPolicy]


@dataclass
class RoleLastUse:
    LastUsedDate: Optional[datetime] = None
    Region: Optional[str] = None


@dataclass
class RoleDetail:
    Path: str
    RoleName: str
    RoleId: str
    Arn: str
    CreateDate: datetime
    AssumeRolePolicyDocument: Document
    InstanceProfileList: List[Any]  # We don't care about this yet
    RolePolicyList: List[Policy] = Field(default_factory=list)
    AttachedManagedPolicies: List[ManagedPolicy] = Field(default_factory=list)
    PermissionsBoundary: Optional[PermissionBoundary] = None
    Tags: List[Tag] = Field(default_factory=list)
    RoleLastUsed: RoleLastUse = Field(...)


@dataclass
class PolicyVersion:
    Document: Document
    VersionId: str
    IsDefaultVersion: bool
    CreateDate: datetime


@dataclass
class PolicyDetail:
    PolicyName: str
    PolicyId: str
    Arn: str
    Path: str
    DefaultVersionId: str
    AttachmentCount: int
    PermissionsBoundaryUsageCount: int
    IsAttachable: bool
    Description: str = Field("")
    CreateDate: datetime = Field(...)
    UpdateDate: datetime = Field(...)
    PolicyVersionList: List[PolicyVersion] = Field(...)


@dataclass
class AuthorizationDetails:
    UserDetailList: List[UserDetail]
    GroupDetailList: List[GroupDetail]
    RoleDetailList: List[RoleDetail]
    Policies: List[PolicyDetail]

    @property
    def account(self) -> str:
        for entity in self.UserDetailList + self.GroupDetailList + self.RoleDetailList + self.Policies:
            if entity.Arn and (account := entity.Arn.split(":")[4]):
                return account

    def get_entity(self, arn: str) -> Union[UserDetail, GroupDetail, RoleDetail, PolicyDetail]:
        for entity in self.UserDetailList + self.GroupDetailList + self.RoleDetailList + self.Policies:
            if entity.Arn == arn:
                return entity


@dataclass
class ResourcePolicy:
    Resource: str
    Policy: Document
    Account: Optional[str] = Field(None)


@dataclass
class SCPPolicy:
    Id: str
    Arn: str
    Name: str
    Description: str
    Type: str
    AwsManaged: bool
    Content: Document

    def __eq__(self, other):
        return self.Arn == other.Arn

    def __hash__(self):
        return hash(self.Arn)


@dataclass
class OrganizationAccount:
    Id: str
    Arn: str
    Email: str
    Name: str
    Status: str
    JoinedMethod: str
    JoinedTimestamp: datetime
    Policies: List[SCPPolicy]
    Type: str = Field(..., pattern="^Account$")
    Parent: Optional[Union[RootOrganization, OrganizationUnit]] = Field(None)

    @property
    def all_policies(self) -> List[SCPPolicy]:
        return self.Policies

    @property
    def all_children(self) -> List[OrganizationAccount]:
        return [self]

    def __eq__(self, other):
        return self.Arn == other.Arn

    def __hash__(self):
        return hash(self.Arn)


@dataclass
class OrganizationUnit:
    Id: str
    Arn: str
    Name: str
    Policies: List[SCPPolicy]
    Children: List[Union[OrganizationUnit, OrganizationAccount]]
    Type: str = Field(..., pattern="^OU$")
    Parent: Optional[Union[RootOrganization, OrganizationUnit]] = Field(None)

    @property
    def all_policies(self) -> List[SCPPolicy]:
        policies = self.Policies

        for child in self.Children:
            policies += child.all_policies

        return policies

    @property
    def all_children(self) -> List[Union[OrganizationAccount, OrganizationUnit]]:
        children = [self]

        for child in self.Children:
            children += child.all_children

        return children

    def set_parents(self):
        for child in self.Children:
            child.Parent = self
            if isinstance(child, OrganizationUnit):
                child.set_parents()

    def find_account(self, account_id: str) -> Optional[OrganizationAccount]:
        for child in self.Children:
            if isinstance(child, OrganizationAccount) and child.Id == account_id:
                return child
            elif isinstance(child, OrganizationUnit):
                if result := child.find_account(account_id):
                    return result

    def __eq__(self, other):
        return self.Arn == other.Arn

    def __hash__(self):
        return hash(self.Arn)


@dataclass
class RootOrganization:
    Id: str
    Arn: str
    Name: str
    PolicyTypes: List[Dict[str, str]]
    Policies: List[SCPPolicy]
    Children: List[Union[OrganizationUnit, OrganizationAccount]]
    Type: str = "Root"
    Parent: None = None

    @property
    def all_policies(self) -> List[SCPPolicy]:
        policies = list(self.Policies)

        for child in self.Children:
            policies += child.all_policies

        return policies

    @property
    def all_children(self) -> List[Union[RootOrganization, OrganizationAccount, OrganizationUnit]]:
        children: List[Union[RootOrganization, OrganizationAccount, OrganizationUnit]] = [self]

        for child in self.Children:
            children += child.all_children

        return children

    def set_parents(self):
        for child in self.Children:
            child.Parent = self
            if isinstance(child, OrganizationUnit):
                child.set_parents()

    def find_account(self, account_id: str) -> Optional[OrganizationAccount]:
        for child in self.Children:
            if isinstance(child, OrganizationAccount) and child.Id == account_id:
                return child
            elif isinstance(child, OrganizationUnit):
                if result := child.find_account(account_id):
                    return result

    def __eq__(self, other):
        return self.Arn == other.Arn

    def __hash__(self):
        return hash(self.Arn)


@dataclass
class DataModel:
    gaads: Dict[str, AuthorizationDetails] = Field(default_factory=dict)
    resource_policies: Dict[str, ResourcePolicy] = Field(default_factory=dict)
    orgs: List[RootOrganization] = Field(default_factory=list)

    @field_validator("resource_policies", mode="before")
    def coerce_resource_policies_to_dict(cls, v):
        if isinstance(v, list):
            return {rp["Resource"] if isinstance(rp, dict) else rp.Resource: rp for rp in v}
        return v

    def get_aws_account(self, account_id: str) -> Optional[OrganizationAccount]:
        for org in self.orgs:
            if account := org.find_account(account_id):
                return account
