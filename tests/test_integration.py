from iamspy import Model
import pathlib
import pytest


@pytest.mark.parametrize(
    "files,inp,out",
    [
        (
            {"gaads": ["role-boundary-no-policies.json"]},
            (
                "arn:aws:iam::123456789012:role/name",
                "lambda:InvokeFunction",
                "arn:aws:lambda:eu-west-1:123456789012:function:helloworld",
            ),
            False,
        ),
        (
            {"gaads": ["user-allow-check.json"]},
            (
                "arn:aws:iam::123456789012:user/PermissionBoundaryAllow",
                "lambda:InvokeFunction",
                "arn:aws:lambda:eu-west-1:123456789012:function:helloworld",
            ),
            True,
        ),
        (
            {"gaads": ["user-boundary-allow.json"]},
            (
                "arn:aws:iam::123456789012:user/PermissionBoundaryAllow",
                "lambda:InvokeFunction",
                "arn:aws:lambda:eu-west-1:123456789012:function:helloworld",
            ),
            True,
        ),
        (
            {"gaads": ["user-boundary-deny.json"]},
            (
                "arn:aws:iam::123456789012:user/name",
                "lambda:InvokeFunction",
                "arn:aws:lambda:eu-west-1:123456789012:function:helloworld",
            ),
            False,
        ),
        (
            {"gaads": ["role-boundary-allow.json"]},
            (
                "arn:aws:iam::123456789012:role/name",
                "lambda:InvokeFunction",
                "arn:aws:lambda:eu-west-1:123456789012:function:helloworld",
            ),
            True,
        ),
        (
            {"gaads": ["role-boundary-deny.json"]},
            (
                "arn:aws:iam::123456789012:role/name",
                "lambda:InvokeFunction",
                "arn:aws:lambda:eu-west-1:123456789012:function:helloworld",
            ),
            False,
        ),
        (
            {"gaads": ["basic-deny.json"]},
            (
                "arn:aws:iam::123456789012:role/name",
                "lambda:InvokeFunction",
                "arn:aws:lambda:eu-west-1:123456789012:function:helloworld",
            ),
            False,
        ),
        (
            {"gaads": ["basic-allow.json"]},
            (
                "arn:aws:iam::123456789012:role/name",
                "lambda:InvokeFunction",
                "arn:aws:lambda:eu-west-1:123456789012:function:helloworld",
            ),
            True,
        ),
        (
            {"gaads": ["basic-allow.json"]},
            (
                "arn:aws:iam::123456789012:role/name",
                "lambda:InvokeFunction",
                "arn:aws:lambda:eu-west-1:111111111111:function:helloworld",
            ),
            False,
        ),
        (
            {"gaads": ["basic-allow.json"], "resources": ["cross-account-rp.json"]},
            (
                "arn:aws:iam::123456789012:role/name",
                "lambda:InvokeFunction",
                "arn:aws:lambda:eu-west-1:111111111111:function:helloworld",
            ),
            True,
        ),
        (
            {"gaads": ["basic-allow.json"], "resources": ["cross-account-rp.json"]},
            (
                "arn:aws:iam::123456789012:role/name2",
                "lambda:InvokeFunction",
                "arn:aws:lambda:eu-west-1:111111111111:function:helloworld",
            ),
            False,
        ),
        (
            {"gaads": ["allow-with-conditions.json"]},
            (
                "arn:aws:iam::123456789012:role/name",
                "lambda:InvokeFunction",
                "arn:aws:lambda:eu-west-1:123456789012:function:helloworld",
            ),
            True,
        ),
        (
            {"gaads": ["allow-with-conditions.json"]},
            (
                "arn:aws:iam::123456789012:role/name",
                "lambda:InvokeFunction",
                "arn:aws:lambda:eu-west-1:123456789012:function:helloworld",
                [],
                None,
                True,
            ),
            False,
        ),
        (
            {"gaads": ["allow-with-conditions.json"]},
            (
                "arn:aws:iam::123456789012:role/name",
                "lambda:InvokeFunction",
                "arn:aws:lambda:eu-west-1:123456789012:function:helloworld",
                ["aws:referer=bobby.tables"],
            ),
            True,
        ),
        (
            {"gaads": ["allow-with-conditions.json"]},
            (
                "arn:aws:iam::123456789012:role/name",
                "lambda:InvokeFunction",
                "arn:aws:lambda:eu-west-1:123456789012:function:helloworld",
                ["aws:referer=bobby.tables"],
                None,
                True,
            ),
            True,
        ),
        (
            {"gaads": ["allow-testing-s3.json"], "resources": ["resource-s3-allow-testing.json"]},
            (
                "arn:aws:iam::111111111111:role/testing",
                "s3:ListBucket",
                "arn:aws:s3:::bucket",
            ),
            True,
        ),
        (
            {"gaads": ["allow-testing-s3.json"], "resources": ["resource-s3-deny-testing2.json"]},
            (
                "arn:aws:iam::111111111111:role/testing2",
                "s3:ListBucket",
                "arn:aws:s3:::bucket",
            ),
            False,
        ),
        (
            {"gaads": ["allow-testing-s3.json"], "resources": ["resource-s3-allow-all.json"]},
            (
                "arn:aws:iam::111111111111:role/testing",
                "s3:ListBucket",
                "arn:aws:s3:::bucket",
            ),
            True,
        ),
        (
            {"gaads": ["basic-deny.json"], "scps": ["scp-basic.json"]},
            (
                "arn:aws:iam::123456789012:role/name",
                "lambda:InvokeFunction",
                "arn:aws:lambda:eu-west-1:123456789012:function:helloworld",
            ),
            False,
        ),
        (
            {"gaads": ["basic-allow.json"], "scps": ["scp-basic.json"]},
            (
                "arn:aws:iam::123456789012:role/name",
                "lambda:InvokeFunction",
                "arn:aws:lambda:eu-west-1:123456789012:function:helloworld",
            ),
            True,
        ),
        (
            {"gaads": ["basic-allow.json"], "scps": ["scp-basic.json"]},
            (
                "arn:aws:iam::123456789012:role/name",
                "lambda:InvokeFunction",
                "arn:aws:lambda:eu-west-1:111111111111:function:helloworld",
            ),
            False,
        ),
        (
            {"gaads": ["basic-allow.json"], "scps": ["scp-deny-lambda.json"]},
            (
                "arn:aws:iam::123456789012:role/name",
                "lambda:InvokeFunction",
                "arn:aws:lambda:eu-west-1:123456789012:function:helloworld",
            ),
            False,
        ),
        (
            {"gaads": ["basic-allow.json"], "scps": ["scp-deny-lambda2.json"]},
            (
                "arn:aws:iam::123456789012:role/name",
                "lambda:InvokeFunction",
                "arn:aws:lambda:eu-west-1:123456789012:function:helloworld",
            ),
            True,
        ),
        # sts:AssumeRole — target role's trust policy (AssumeRolePolicyDocument)
        # must be honoured as the resource policy even though it is not loaded
        # via load_resource_policies. Same-account assume is allowed iff the
        # caller has identity permission AND the target trust allows the caller.
        # Explicit-principal trust naming the caller role exactly.
        (
            {"gaads": ["assume-role-trust.json"]},
            (
                "arn:aws:iam::111111111111:role/Caller",
                "sts:AssumeRole",
                "arn:aws:iam::111111111111:role/TrustingRole",
            ),
            True,
        ),
        # Account-root (":root") trust delegates to identity policies in the
        # account; the caller has sts:AssumeRole identity permission, so allowed.
        (
            {"gaads": ["assume-role-trust.json"]},
            (
                "arn:aws:iam::111111111111:role/Caller",
                "sts:AssumeRole",
                "arn:aws:iam::111111111111:role/RootTrust",
            ),
            True,
        ),
        # Target trust does not name the caller and is not a :root delegation,
        # so the assume must be denied even though identity allows it.
        (
            {"gaads": ["assume-role-trust.json"]},
            (
                "arn:aws:iam::111111111111:role/Caller",
                "sts:AssumeRole",
                "arn:aws:iam::111111111111:role/NoTrust",
            ),
            False,
        ),
        # :root trust delegates to identity policies, so a caller WITHOUT the
        # sts:AssumeRole identity permission is still denied.
        (
            {"gaads": ["assume-role-trust.json"]},
            (
                "arn:aws:iam::111111111111:role/NoIdentityCaller",
                "sts:AssumeRole",
                "arn:aws:iam::111111111111:role/RootTrust",
            ),
            False,
        ),
    ],
)
def test_can_i(files, inp, out):
    m = Model()

    base_path = pathlib.Path(__file__).parent / "files"

    for gaad in files.get("gaads", []):
        m.load_gaad(base_path / gaad)

    for rp in files.get("resources", []):
        m.load_resource_policies(base_path / rp)

    for scp in files.get("scps", []):
        m.load_scps(base_path / scp)

    assert m.can_i(*inp) == out


@pytest.mark.parametrize(
    "files,inp,out",
    [
        (
            {"gaads": ["role-boundary-no-policies.json"]},
            (
                "lambda:InvokeFunction",
                "arn:aws:lambda:eu-west-1:123456789012:function:helloworld",
            ),
            set([]),
        ),
        (
            {"gaads": ["user-allow-check.json"]},
            (
                "lambda:InvokeFunction",
                "arn:aws:lambda:eu-west-1:123456789012:function:helloworld",
            ),
            set(["arn:aws:iam::123456789012:user/PermissionBoundaryAllow"]),
        ),
        (
            {"gaads": ["user-boundary-allow.json"]},
            (
                "lambda:InvokeFunction",
                "arn:aws:lambda:eu-west-1:123456789012:function:helloworld",
            ),
            set(["arn:aws:iam::123456789012:user/PermissionBoundaryAllow"]),
        ),
        (
            {"gaads": ["user-boundary-deny.json"]},
            (
                "lambda:InvokeFunction",
                "arn:aws:lambda:eu-west-1:123456789012:function:helloworld",
            ),
            set(),
        ),
        (
            {"gaads": ["role-boundary-allow.json"]},
            (
                "lambda:InvokeFunction",
                "arn:aws:lambda:eu-west-1:123456789012:function:helloworld",
            ),
            set(["arn:aws:iam::123456789012:role/name"]),
        ),
        (
            {"gaads": ["role-boundary-deny.json"]},
            (
                "lambda:InvokeFunction",
                "arn:aws:lambda:eu-west-1:123456789012:function:helloworld",
            ),
            set(),
        ),
        (
            {"gaads": ["basic-allow.json"]},
            (
                "lambda:InvokeFunction",
                "arn:aws:lambda:eu-west-1:123456789012:function:helloworld",
            ),
            set(["arn:aws:iam::123456789012:role/name"]),
        ),
        (
            {"gaads": ["allow-testing-s3.json"], "resources": ["resource-s3-allow-testing.json"]},
            (
                "s3:ListBucket",
                "arn:aws:s3:::bucket",
            ),
            set(["arn:aws:iam::111111111111:role/testing", "arn:aws:iam::111111111111:role/testing2"]),
        ),
        (
            {"gaads": ["basic-allow.json"], "resources": ["cross-account-rp.json"]},
            (
                "lambda:InvokeFunction",
                "arn:aws:lambda:eu-west-1:111111111111:function:helloworld",
            ),
            set(["arn:aws:iam::123456789012:role/name"]),
        ),
        (
            {"gaads": ["allow-with-conditions.json"]},
            (
                "lambda:InvokeFunction",
                "arn:aws:lambda:eu-west-1:123456789012:function:helloworld",
            ),
            set(["arn:aws:iam::123456789012:role/name"]),
        ),
        (
            {"gaads": ["allow-with-conditions.json"]},
            (
                "lambda:InvokeFunction",
                "arn:aws:lambda:eu-west-1:123456789012:function:helloworld",
                [],
                None,
                True,
            ),
            set(),
        ),
        (
            {"gaads": ["allow-with-conditions.json"]},
            (
                "lambda:InvokeFunction",
                "arn:aws:lambda:eu-west-1:123456789012:function:helloworld",
                ["aws:referer=bobby.tables"],
            ),
            set(["arn:aws:iam::123456789012:role/name"]),
        ),
        (
            {"gaads": ["allow-with-conditions.json"]},
            (
                "lambda:InvokeFunction",
                "arn:aws:lambda:eu-west-1:123456789012:function:helloworld",
                ["aws:referer=bobby.tables"],
                None,
                True,
            ),
            set(["arn:aws:iam::123456789012:role/name"]),
        ),
        (
            {"gaads": ["allow-testing-s3.json"], "resources": ["resource-s3-allow-testing.json"]},
            (
                "s3:ListBucket",
                "arn:aws:s3:::bucket",
            ),
            set(["arn:aws:iam::111111111111:role/testing", "arn:aws:iam::111111111111:role/testing2"]),
        ),
        (
            {"gaads": ["allow-testing-s3.json"], "resources": ["resource-s3-deny-testing2.json"]},
            (
                "s3:ListBucket",
                "arn:aws:s3:::bucket",
            ),
            set([]),
        ),
        (
            {"gaads": ["allow-testing-s3.json"], "resources": ["resource-s3-allow-all.json"]},
            (
                "s3:ListBucket",
                "arn:aws:s3:::bucket",
            ),
            set(["arn:aws:iam::111111111111:role/testing", "arn:aws:iam::111111111111:role/testing2"]),
        ),
        (
            {"gaads": ["gaad-uppercase.json"], "resources": ["resource-uppercase.json"]},
            (
                "s3:GetObject",
                "arn:aws:s3:::bucket/key",
            ),
            set(["arn:aws:iam::111111111111:user/userA", "arn:aws:iam::111111111111:user/userB"]),
        ),
        # who-can sts:AssumeRole resolves the target role's trust policy from the
        # GAAD: only the caller with both identity permission and trust matches.
        (
            {"gaads": ["assume-role-trust.json"]},
            (
                "sts:AssumeRole",
                "arn:aws:iam::111111111111:role/RootTrust",
            ),
            set(["arn:aws:iam::111111111111:role/Caller"]),
        ),
    ],
)
def test_who_can(files, inp, out):
    m = Model()

    base_path = pathlib.Path(__file__).parent / "files"

    for gaad in files.get("gaads", []):
        m.load_gaad(base_path / gaad)

    for rp in files.get("resources", []):
        m.load_resource_policies(base_path / rp)

    for scp in files.get("scps", []):
        m.load_scps(base_path / scp)

    assert set(m.who_can(*inp)) == out


@pytest.mark.parametrize(
    "files,inp,out",
    [
        (
            {"gaads": ["batch-allow.json"], "resources": ["batch-resource.json"]},
            (
                "s3:GetObject",
                [
                    "arn:aws:s3:::bucket1/foo",
                    "arn:aws:s3:::bucket2/foo",
                    "arn:aws:s3:::bucket3/foo",
                    "arn:aws:s3:::bucket4/foo",
                ],
            ),
            set(
                [
                    ("arn:aws:iam::123456789012:role/name1", "arn:aws:s3:::bucket1/foo"),
                    ("arn:aws:iam::123456789012:role/name1", "arn:aws:s3:::bucket2/foo"),
                    ("arn:aws:iam::123456789012:role/name2", "arn:aws:s3:::bucket2/foo"),
                    ("arn:aws:iam::123456789012:role/name3", "arn:aws:s3:::bucket4/foo"),
                ]
            ),
        )
    ],
)
def test_who_can_batch_resource(files, inp, out):
    m = Model()

    base_path = pathlib.Path(__file__).parent / "files"

    for gaad in files.get("gaads", []):
        m.load_gaad(base_path / gaad)

    for rp in files.get("resources", []):
        m.load_resource_policies(base_path / rp)

    for scp in files.get("scps", []):
        m.load_scps(base_path / scp)

    assert set(m.who_can_batch_resource(*inp)) == out
