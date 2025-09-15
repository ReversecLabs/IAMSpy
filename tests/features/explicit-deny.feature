Feature: Explicit Deny
	Background:
		Given I'm using arn:aws:iam::111111111111:role/source-deny with the policy:
			[{
				"Effect": "Deny",
				"Action": "*",
				"Resource": "*"
			}]

	Scenario: Same account root ARN trust
		Given I have the resource arn:aws:iam::111111111111:role/target with the trust policy:
			[{
				"Effect": "Allow",
				"Principal": { "AWS": "arn:aws:iam::111111111111:root" },
				"Action": "sts:AssumeRole"
			}]
		When I call sts:AssumeRole on the resource
		Then Access should be denied

	Scenario: Same account explicit ARN trust
		Given I have the resource arn:aws:iam::111111111111:role/target with the trust policy:
			[{
				"Effect": "Allow",
				"Principal": { "AWS": "arn:aws:iam::111111111111:role/source-deny" },
				"Action": "sts:AssumeRole"
			}]
		When I call sts:AssumeRole on the resource
		Then Access should be denied

	Scenario: Cross account explicit ARN trust
		Given I have the resource arn:aws:iam::999999999999:role/target with the trust policy:
			[{
			"Effect": "Allow",
			"Principal": { "AWS": "arn:aws:iam::111111111111:role/source-deny" },
			"Action": "sts:AssumeRole"
			}]
		When I call sts:AssumeRole on the resource
		Then Access should be denied