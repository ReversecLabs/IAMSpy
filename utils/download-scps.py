import boto3
import json
import sys
from functools import lru_cache

DEFAULT_FILENAME = "scps.json"

HELP_MESSAGE = f"""Quickly downloads an AWS Organizations OU structure and SCPs to be fed into IAMSpy

Usage: python3 download-scps.py OUTPUT_FILE

OUTPUT_FILE defaults to {DEFAULT_FILENAME}, however can be set to stdout by setting it to -"""


def print_stderr(s):
    print(s, file=sys.stderr)


def handle_next_token(api_call, response_key, **kwargs):
    resp = api_call(**kwargs)

    results = resp[response_key]

    token = resp.get("NextToken", None)
    while token:
        resp = api_call(NextToken=token, **kwargs)
        results.extend(resp[response_key])
        token = resp.get("NextToken", None)

    return results


client = boto3.client(service_name="organizations")


def get_roots():
    return handle_next_token(client.list_roots, "Roots")


@lru_cache
def get_policy(policy_id):
    return json.loads(client.describe_policy(PolicyId=policy_id)["Policy"]["Content"])


all_accounts = {}


def get_account(account_id):
    if not all_accounts:
        for account in handle_next_token(client.list_accounts, "Accounts"):
            all_accounts[account["Id"]] = account

    return all_accounts.get(account_id, {
        "Id": account_id,
        "Name": f"Deactivated-Account-{account_id}",
        "Status": "SUSPENDED_OR_DEACTIVATED"
    })



def get_policies(target_id):
    policies = handle_next_token(
        client.list_policies_for_target,
        "Policies",
        TargetId=target_id,
        Filter="SERVICE_CONTROL_POLICY",
    )

    for policy in policies:
        policy["Content"] = get_policy(policy["Id"])

    return policies


def get_children(parent):
    parent_id = parent["Id"]
    print_stderr(f"Fetching data for {parent_id}")
    ous = handle_next_token(
        client.list_children,
        "Children",
        ParentId=parent_id,
        ChildType="ORGANIZATIONAL_UNIT",
    )
    accounts = handle_next_token(
        client.list_children,
        "Children",
        ParentId=parent_id,
        ChildType="ACCOUNT",
    )

    resp = parent

    resp["Policies"] = get_policies(resp["Id"])

    if ous:
        ous = [
            get_children(
                client.describe_organizational_unit(OrganizationalUnitId=x["Id"])["OrganizationalUnit"],
            )
            for x in ous
        ]
        ous = [{**x, "Type": "OU"} for x in ous]

    if accounts:
        resolved_accounts = []
        for x in accounts:
            account_data = get_account(x["Id"])
            try:
                policies = get_policies(x["Id"])
            except Exception as e:
                print_stderr(f"Warning: Could not fetch policies for account {x['Id']}: {e}")
                policies = [] # fallback to empty list

            resolved_accounts.append({**account_data, "Policies": policies, "Type": "Account"})
        accounts = resolved_accounts

    resp["Children"] = ous + accounts

    return resp


if len(sys.argv) < 2:
    print_stderr(f"No output filename given, defaulting to {DEFAULT_FILENAME}")
    filename = DEFAULT_FILENAME
else:
    filename = sys.argv[1]
    if sys.argv[1] in ["-h", "--help"]:
        print_stderr(HELP_MESSAGE)
        sys.exit()

output = get_children(get_roots()[0])

if filename == "-":
    file = sys.stdout
else:
    file = open(filename, "w")

json.dump(output, file, indent=4, default=str)