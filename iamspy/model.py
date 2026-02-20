from typing import List, Optional, Set, Union, Tuple
import logging
import json
import z3
import hashlib
from dataclasses import asdict
from pathlib import Path
from iamspy.iam import AuthorizationDetails, ResourcePolicy, RootOrganization, DataModel, json_serial
from iamspy import parse
from iamspy.parse import add_source, add_resource, add_account_scps
from iamspy.datatypes import parse_string
from iamspy.utils import get_conditions, get_vars


logger = logging.getLogger("iamspy.model")


class Model:
    def __init__(self):
        self.solver = z3.Solver()
        self._model = DataModel()
        self.data = {}
        self._model_vars = None
        self.call_args = {}

    def __old_enter__(self):
        new_solver = z3.Solver()
        new_solver.add(*list(self.solver.assertions()))
        return new_solver

    def __old_exit__(self, exc_type, exc_value, exc_traceback):
        pass

    def _save(self, filename: str):
        """
        Save a generated Z3 model to a file
        """
        output = {"model": self.solver.to_smt2(), "vars": list(self.model_vars)}
        with open(filename, "w") as fs:
            json.dump(output, fs)

    def save(self, filename: str):
        """
        Save the current model to a file
        """
        output = asdict(self._model)
        with open(filename, "w") as fs:
            json.dump(output, fs, default=json_serial)

    def _load_model(self, filename: str):
        """
        Load an existing Z3 model from a file.
        """
        try:
            with open(filename) as fs:
                data = json.load(fs)
            self.solver.from_string(data["model"])
            self._model_vars = set(data["vars"])
        except json.JSONDecodeError:
            self.solver.from_file(filename)
            self._model_vars = None

    def load_model(self, filename: str):
        """
        Load an existing model from a file
        """
        try:
            data = json.load(open(filename))
            self._model = DataModel(**data)
        except json.JSONDecodeError:
            pass

    def generate_conditions(
        self,
        model_conditions: Set[str],
        conditions: Optional[List[str]],
        condition_file: Optional[str],
        strict_conditions: bool = False,
    ):
        output = []
        provided_conditions = set()

        if conditions:
            for condition in conditions:
                key, value = condition.split("=")
                provided_conditions.add(key)
                logger.debug(f"Adding constraint to set {key} condition as {value}")
                output.append(z3.String(f"condition_{key}") == z3.StringVal(value))

        if condition_file:
            logger.debug(f"Parsing {condition_file}")
            condition_file_data = json.load(open(condition_file))
            output.append(parse._parse_condition(condition_file_data))
            for test, variables in condition_file_data.items():
                for key, value in variables.items():
                    provided_conditions.add(key)

        if strict_conditions:
            logger.debug(f"Non existent conditions from request are: {model_conditions - provided_conditions}")

            for condition in model_conditions - provided_conditions:
                output.append(z3.Bool(f"condition_{condition}_exists") == False)

            for condition in provided_conditions:
                output.append(z3.Bool(f"condition_{condition}_exists"))

        return output

    def generate_solver(
        self,
        source: Optional[Union[str, List[str]]] = None,
        action: Optional[str] = None,
        resource: Optional[Union[str, List[str]]] = None,
        conditions: Optional[List[str]] = None,
        condition_file: Optional[str] = None,
        strict_conditions: bool = False,
    ):
        """
        Generate the Z3 solver from the data model.
        """
        solver = z3.Solver()

        # Source
        if source:
            if isinstance(source, str):
                source = [source]

            for entity in source:
                account_id = entity.split(":")[4]
                try:
                    gaad = self._model.gaads[account_id]
                except KeyError:
                    logger.debug(f"No GAAD for {entity}, setting to false")
                    solver.add(z3.Bool(f"identity_{entity}") == False)
                else:
                    solver.add(*add_source(gaad, entity))

            account_ids = set(x.split(":")[4] for x in source)
            accounts = [self._model.get_aws_account(x) for x in account_ids]
            accounts = [x for x in accounts if x]
            if accounts:
                solver.add(*add_account_scps(accounts))

            logger.debug(f"Adding constraint source is {source}")
            solver.add(
                z3.Or(
                    *[
                        z3.And(
                            parse_string(z3.String("s"), entity, wildcard=False),
                            z3.String("s_account") == z3.StringVal(entity.split(":")[4]),
                            z3.Bool(f"deny_identity_{entity}"),
                        )
                        for entity in source
                    ]
                )
            )
            # An identity variable that can be used for further logic checks
            solver.add(
                z3.Bool("identity")
                == z3.Or(
                    *[
                        z3.And(
                            parse_string(z3.String("s"), entity, wildcard=False),
                            z3.Bool(f"identity_{entity}"),
                        )
                        for entity in source
                    ]
                )
            )

        # Action
        logger.debug(f"Adding constraint action is {action}")
        solver.add(parse_string(z3.String("a"), action, wildcard=False))

        # Resources
        if resource:
            if isinstance(resource, str):
                resource = [resource]

            additional_buckets = set()
            for res in resource:
                if res.startswith("arn:aws:s3:::") and "/" in res:
                    # This is for a bucket object, needs to follow bucket policy of the bucket
                    # so need to load the bucket
                    bucket = res.split("/")[0]
                    if bucket not in resource:
                        additional_buckets.add(bucket)
            resource = list(additional_buckets) + resource

            for res in resource:
                solver.add(*add_resource(self._model.resource_policies, res))
            logger.debug(f"Adding constraint resource is {resource}")
            solver.add(
                z3.Or(
                    *[
                        z3.And(
                            parse_string(z3.String("r"), x, wildcard=False),
                            z3.String("r_account") == z3.String(f"resource_{x}_account"),
                            z3.Bool(f"deny_resource_{x}"),
                        )
                        for x in resource
                    ]
                )
            )
            # A resource variable that can be used for further logic checks
            solver.add(
                z3.Bool("resource")
                == z3.Or(
                    *[
                        z3.And(
                            parse_string(z3.String("r"), x, wildcard=False),
                            z3.Bool(f"resource_{x}"),
                        )
                        for x in resource
                    ]
                )
            )

        # Conditions
        model_vars = get_vars(list(solver.assertions()))
        model_conditions = get_conditions(model_vars)
        solver.add(
            *self.generate_conditions(
                model_conditions,
                conditions,
                condition_file,
                strict_conditions,
            )
        )

        # Additional validations

        solver.add(z3.Or(z3.Bool("identity"), z3.Bool("resource")))

        # certain actions always require resource trust policy approval
        for action in ["sts:assumerole"]:
            solver.add(
                z3.Or(
                    z3.And(parse_string(z3.String("a"), action), z3.Bool("resource")),
                    z3.Not(parse_string(z3.String("a"), action)),
                )
            )

        # cross account must have both identity and resource pass
        solver.add(
            z3.Or(
                z3.String("s_account") == z3.String("r_account"),
                z3.And(
                    z3.Bool("identity"),
                    z3.Bool("resource"),
                ),
            )
        )

        return solver

    def _load_gaad(self, filename: str) -> AuthorizationDetails:
        """
        Load the output of `aws iam get-account-authorization-details`

        Returns a python object representation of the JSON doc, after adding
        the model to the Z3 solver.
        """
        auth_details = AuthorizationDetails(**json.load(open(filename)))
        conditions = parse.generate_model(auth_details)
        self.solver.add(*conditions)
        self._model_vars = None
        return auth_details

    def load_gaad(self, filename: str) -> AuthorizationDetails:
        """
        Load the output of `aws iam get-account-authorization-details`

        Returns a python object representation of the JSON doc, after adding
        the model to the Data Model
        """
        auth_details = AuthorizationDetails(**json.load(open(filename)))
        self._model.gaads[auth_details.account] = auth_details
        return auth_details

    def load_gaads(self, folder: str) -> None:
        """
        Load the output of `aws iam get-account-authorization-details`

        Returns a python object representation of the JSON doc, after adding
        the model to the Data Model
        """
        for filename in Path(folder).glob("*.json"):
            auth_details = AuthorizationDetails(**json.load(open(filename)))
            self._model.gaads[auth_details.account] = auth_details

    def _load_resource_policies(self, filename: str) -> None:
        """
        Load resource policies in from a JSON file
        """
        policies = [ResourcePolicy(**item) for item in json.load(open(filename))]
        for policy in policies:
            self.solver.add(*parse.parse_resource_policy(policy.Resource, policy.Policy, policy.Account))
        self._model_vars = None

    def load_resource_policies(self, filename: str) -> List[ResourcePolicy]:
        """
        Load resource policies in from a JSON file
        """
        policies = [ResourcePolicy(**item) for item in json.load(open(filename))]
        self._model.resource_policies.extend(policies)
        return policies

    def _load_scps(self, filename: str) -> None:
        """
        Load SCPs in from a JSON file
        """
        org = RootOrganization(**json.load(open(filename)))

        self.solver.add(*parse.parse_scps(org))

        self._model_vars = None

    def load_scps(self, filename: str) -> RootOrganization:
        org = RootOrganization(**json.load(open(filename)))
        org.set_parents()

        self._model.orgs.append(org)

        return org

    @property
    def model_vars(self) -> Set[str]:
        # Try loading from file
        if self._model_vars is None:
            try:
                with open("model.vars") as fs:
                    logger.warn("model.vars has now been deprecated, please re-save the model and delete this file")
                    data = fs.read()
                    h, v = data.split("\n", 1)
                    if h == self.hash:
                        logger.info("Loading model vars from model.vars")
                        self._model_vars = set(v.split("\n"))
                    else:
                        logger.info("model.vars hash does not match current model")
            except FileNotFoundError:
                pass

        # Re-generate the model vars
        if self._model_vars is None:
            self._model_vars = get_vars(list(self.solver.assertions()))

        return self._model_vars

    @property
    def hash(self):
        return hashlib.md5(self.solver.to_smt2().encode()).hexdigest()

    def generate_evaluation_logic_checks(
        self, source: Optional[Union[str, List[str]]], resource: Union[str, List[str]]
    ):
        """
        Generate the assertions for the model
        """
        if isinstance(resource, str):
            resource = [resource]

        return parse.generate_evaluation_logic_checks(self.model_vars, source, resource)

    def _generate_query_conditions(
        self,
        source: Optional[Union[str, List[str]]],
        action: str,
        resource: Union[str, List[str]],
        conditions: Optional[List[str]] = None,
        condition_file: Optional[str] = None,
        strict_conditions: bool = False,
        model_conditions: Set[str] = set(),
    ):
        if conditions is None:
            conditions = []

        if isinstance(resource, str):
            resource = [resource]

        output = self.generate_evaluation_logic_checks(source, resource)

        return output

    def get_correct_case_principal(self, principal: str) -> str:
        account_id = principal.split(":")[4]
        entity_type = principal.split(":")[5].split("/")[0]

        gaad = self._model.gaads[account_id]
        try:
            if entity_type == "user":
                entity = next(x for x in gaad.UserDetailList if x.Arn.lower() == principal.lower())
            else:
                entity = next(x for x in gaad.RoleDetailList if x.Arn.lower() == principal.lower())
        except StopIteration:
            raise ValueError(f"Principal {principal} not found in GAAD for account {account_id}")

        return entity.Arn

    def _check_viable_source_accounts(self, action: str, resource: str) -> Set[str]:
        print("Checking now")
        all_source_accounts = list(self._model.gaads.keys())
        try:
            if resource.startswith("arn:aws:s3:::") and "/" in resource:
                bucket = resource.split("/")[0]
                rp = [p for p in self._model.resource_policies if p.Resource == bucket]
            else:
                rp = [p for p in self._model.resource_policies if p.Resource == resource]
        except StopIteration:
            # No resource policy, assume same account only (unless it's an S3 bucket)
            if resource.startswith("arn:aws:s3:::"):
                return set(all_source_accounts)
            else:
                return set([resource.split(":")[4]])

        solver = self.generate_solver(
            source=None,
            action=action,
            resource=resource,
        )
        solver.add(z3.Bool("identity") == True)
        solver.add(
            z3.Or(
                *[
                    z3.And(
                        parse_string(z3.String("s"), f"arn:aws:iam::{account}:*"),
                        z3.String(f"s_account") == z3.StringVal(account),
                    )
                    for account in all_source_accounts
                ]
            )
        )

        accounts = set()
        while solver.check() == z3.sat:
            m = solver.model()
            account = str(m[z3.String("s_account")])[1:-1]
            accounts.add(account)
            solver.add(z3.String("s_account") != z3.StringVal(account))

        logger.debug(f"Viable source accounts for {resource} are: {accounts}")
        return accounts

    def _can_i(
        self,
        source: str,
        action: str,
        resource: str,
        conditions: List[str] = [],
        condition_file: Optional[str] = None,
        strict_conditions: bool = False,
        debug: bool = False,
    ) -> bool:
        """
        Used by the CLI to provide the can-i call.
        """
        with self as solver:
            logger.debug("Identifying model conditions")
            model_conditions = get_conditions(self.model_vars)
            logger.debug(f"Model conditions identified as: {model_conditions}")

            query_conditions = self._generate_query_conditions(
                source=source,
                action=action,
                resource=resource,
                conditions=conditions,
                condition_file=condition_file,
                strict_conditions=strict_conditions,
                model_conditions=model_conditions,
            )

            solver.add(*query_conditions)

            if debug:
                return solver
            else:
                return solver.check() == z3.sat

    def can_i(
        self,
        source: str,
        action: str,
        resource: str,
        conditions: List[str] = [],
        condition_file: Optional[str] = None,
        strict_conditions: bool = False,
        debug: bool = False,
    ) -> bool:
        """
        Used by the CLI to provide the can-i call.
        """

        solver = self.generate_solver(
            source=source,
            action=action,
            resource=resource,
            conditions=conditions,
            condition_file=condition_file,
            strict_conditions=strict_conditions,
        )

        if debug:
            return solver
        else:
            return solver.check() == z3.sat

        return False

    def _who_can(
        self,
        action: str,
        resource: str,
        conditions: List[str] = [],
        condition_file: Optional[str] = None,
        strict_conditions: bool = False,
    ) -> list[str]:
        """
        Used by the CLI to provide the who-can call.
        """
        with self as solver:
            logger.debug("Identifying model conditions")
            model_conditions = get_conditions(self.model_vars)
            logger.debug(f"Model conditions identified as: {model_conditions}")

            query_conditions = self._generate_query_conditions(
                source=None,
                action=action,
                resource=resource,
                conditions=conditions,
                condition_file=condition_file,
                strict_conditions=strict_conditions,
                model_conditions=model_conditions,
            )

            logger.debug("Adding generated query conditions")
            # solver.set(threads=4)
            solver.add(*query_conditions)
            sat = solver.check() == z3.sat
            sources = []
            while sat:
                s = z3.String("s")
                m = solver.model()
                source = m[s]
                logger.debug(f"Found {source} as a potential candidate")
                sources.append(str(source)[1:-1])
                yield self.get_correct_case_principal(str(source)[1:-1])
                solver.add(s != source)
                sat = solver.check() == z3.sat

    def who_can(
        self,
        action: str,
        resource: str,
        conditions: List[str] = [],
        condition_file: Optional[str] = None,
        strict_conditions: bool = False,
    ) -> list[str]:
        """
        Used by the CLI to provide the who-can call.
        """
        possible_accounts = self._check_viable_source_accounts(action, resource)

        for gaad in self._model.gaads.values():
            if gaad.account not in possible_accounts:
                logger.debug(f"Skipping {gaad.account} GAAD as not a viable source account for {resource}")
                continue
            logger.debug(f"Checking identities in {gaad.account} GAAD")
            sources = set()
            for identity in gaad.RoleDetailList + gaad.UserDetailList:
                sources.add(identity.Arn)

            solver = self.generate_solver(
                source=list(sources),
                action=action,
                resource=resource,
                conditions=conditions,
                condition_file=condition_file,
                strict_conditions=strict_conditions,
            )

            sat = solver.check() == z3.sat
            while sat:
                s = z3.String("s")
                m = solver.model()
                source = m[s]
                logger.debug(f"Found {source} as a potential candidate")
                yield self.get_correct_case_principal(str(source)[1:-1])
                solver.add(s != source)
                sat = solver.check() == z3.sat

    def which_can_i(
        self,
        source_arn: str,
        action: str,
        resources: List[str],
        conditions: List[str] = [],
        condition_file: Optional[str] = None,
        strict_conditions: bool = False,
    ) -> List[str]:
        """
        Used by the CLI to provide the which-can-i call.
        """
        with self as solver:
            logger.debug("Identifying model conditions")
            model_conditions = get_conditions(self.model_vars)
            logger.debug(f"Model conditions identified as: {model_conditions}")

            query_conditions = self._generate_query_conditions(
                source=source_arn,
                action=action,
                resource=resources,
                conditions=conditions,
                condition_file=condition_file,
                strict_conditions=strict_conditions,
                model_conditions=model_conditions,
            )

            logger.debug("Adding generated query conditions")
            # solver.set(threads=4)
            solver.add(*query_conditions)
            sat = solver.check() == z3.sat
            while sat:
                r = z3.String("r")
                m = solver.model()
                resource = m[r]
                logger.debug(f"Found {resource} as a potential candidate")
                yield str(resource)[1:-1]
                solver.add(r != resource)
                sat = solver.check() == z3.sat

    def who_can_batch_resource(
        self,
        action: str,
        resources: List[str],
        conditions: List[str] = [],
        condition_file: Optional[str] = None,
        strict_conditions: bool = False,
    ) -> List[Tuple[str, str]]:
        with self as solver:
            logger.debug("Identifying model conditions")
            model_conditions = get_conditions(self.model_vars)
            logger.debug(f"Model conditions identified as: {model_conditions}")

            query_conditions = self._generate_query_conditions(
                source=None,
                action=action,
                resource=resources,
                conditions=conditions,
                condition_file=condition_file,
                strict_conditions=strict_conditions,
                model_conditions=model_conditions,
            )

            logger.debug("Adding generated query conditions")
            solver.set(threads=4)
            solver.add(*query_conditions)
            sat = solver.check() == z3.sat
            results = []
            while sat:
                s = z3.String("s")
                r = z3.String("r")
                m = solver.model()
                source = m[s]
                resource = m[r]
                logger.debug(f"Found {source} as a potential candidate for {resource}")
                results.append((str(source)[1:-1], str(resource)[1:-1]))
                solver.add(z3.Not(z3.And(s == source, r == resource)))
                sat = solver.check() == z3.sat
            return results

    def supports_external(self) -> List[str]:
        with self as solver:
            output = self.generate_evaluation_logic_checks(None, resource)
            s, a, r = z3.Strings("s a r")
            output.append(parse_string(a, action, wildcard=False))
            output.append(z3.Or(*[parse_string(r, x, wildcard=False) for x in resource]))
            solver.add(*output)
            return solver.check() == z3.sat
