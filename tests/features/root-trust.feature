Feature: Root Trust
	Background:
		Given I'm using arn:aws:iam::111111111111:role/source with the policy:
			[{
				"Effect": "Allow",
				"Action": "sts:AssumeRole",
				"Resource": "*"
			}]

	Scenario: Same account AssumeRole request.
		Given I have the resource arn:aws:iam::111111111111:role/target with the trust policy:
			[{
				"Effect": "Allow",
				"Principal": { "AWS": "arn:aws:iam::111111111111:root" },
				"Action": "sts:AssumeRole"
			}]
		When I call sts:AssumeRole on the resource
		Then Access should be allowed