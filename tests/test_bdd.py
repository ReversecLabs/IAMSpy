import json
from datetime import datetime

from iamspy.iam import RoleDetail, Document, Policy, RoleLastUse, ResourcePolicy
from iamspy.parse import _parse_role, parse_resource_policy
from pytest_bdd import scenarios, given, when, then, parsers
from pytest_bdd.parsers import parse

from .fixtures.role import *

scenarios("features")

@pytest.fixture
def source() -> 'RoleDetail':
    return RoleDetail(
        Path="/",
        RoleName="source",
        CreateDate=datetime.now(),
        RoleLastUsed=RoleLastUse(LastUsedDate=datetime.now(), Region="us-east-1"),
        RoleId="AORAXXXXXXXXXXXXXXXXX",
        Arn=f"arn:aws:iam::111111111111:role/source",
        AssumeRolePolicyDocument=Document(),
        InstanceProfileList=[],
        RolePolicyList=[],
    )


@given(parsers.parse("I'm using {arn} with the policy:\n{policy}"))  # Step alias
def set_source(model, req, source, arn, policy):
    source.Arn = arn
    source.RoleName = arn.split(':')[5].split("/")[-1]
    source.RolePolicyList.append(Policy(
        PolicyName="identity_policy",
        PolicyDocument=Document(Statement=json.loads(policy)),
    ))


@pytest.fixture
def resource():
    return ResourcePolicy(
        Resource="target",
        Policy=Document(),
        Account="111111111111",
    )


@given(parse("I have the resource {arn} with the trust policy:\n{policy}"))
def set_resource(resource, arn, policy):
    resource.Resource = arn
    resource.Account = arn.split(':')[4]
    resource.Policy = Document(Statement=json.loads(policy))


@when(parsers.parse("I call {action}"))
def call(req, model, source, action, resource):
    model.solver.add(*_parse_role(None, source))
    model.solver.add(*parse_resource_policy(resource.Resource, resource.Policy, resource.Account))
    req["source"] = source.Arn
    req["action"] = action
    req["resource"] = resource.Resource


@then(parsers.parse("Access should be allowed"))
def allowed(model, req):
    assert model.can_i(**req)


@then(parsers.parse("Access should be denied"))
def denied(model, req):
    assert not model.can_i(**req, strict_conditions=True)