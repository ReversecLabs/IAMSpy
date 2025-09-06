from typing import List, Optional, Set, Union, Tuple
import logging
import json
import z3
import hashlib
from iamspy.iam import AuthorizationDetails, ResourcePolicy, RootOrganization
from iamspy import parse
from iamspy.datatypes import parse_string
from iamspy.utils import get_conditions, get_vars


logger = logging.getLogger("iamspy.model")


class Model:
    def __init__(self):
        self.solver = z3.Solver()
        self._model_vars = None

    def __enter__(self):
        new_solver = z3.Solver()
        new_solver.add(*list(self.solver.assertions()))
        return new_solver

    def __exit__(self, exc_type, exc_value, exc_traceback):
        pass

    def save(self, filename: str):
        """
        Save a generated Z3 model to a file
        """
        output = {"model": self.solver.to_smt2(), "vars": list(self.model_vars)}
        with open(filename, "w") as fs:
            json.dump(output, fs)

    def load_model(self, filename: str):
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

    def load_gaad(self, filename: str) -> AuthorizationDetails:
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

    def load_resource_policies(self, filename: str) -> None:
        """
        Load resource policies in from a JSON file
        """
        policies = [ResourcePolicy(**item) for item in json.load(open(filename))]
        for policy in policies:
            self.solver.add(*parse.parse_resource_policy(policy.Resource, policy.Policy, policy.Account))
        self._model_vars = None

    def load_scps(self, filename: str) -> None:
        """
        Load SCPs in from a JSON file
        """
        org = RootOrganization(**json.load(open(filename)))

        self.solver.add(*parse.parse_scps(org))

        self._model_vars = None

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

    def generate_evaluation_logic_checks(self, source: Optional[str], resource: Union[str, List[str]]):
        """
        Generate the assertions for the model
        """
        if isinstance(resource, str):
            resource = [resource]

        return parse.generate_evaluation_logic_checks(self.model_vars, source, resource)

    def _generate_query_conditions(
        self,
        source: Optional[str],
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

        s, a, r = z3.Strings("s a r")

        if source is not None:
            logger.debug(f"Adding constraint source is {source}")
            output.append(parse_string(s, source, wildcard=False))
        logger.debug(f"Adding constraint action is {action}")
        logger.debug(f"Adding constraint resource is {resource}")
        output.append(parse_string(a, action, wildcard=False))
        output.append(z3.Or(*[parse_string(r, x, wildcard=False) for x in resource]))

        provided_conditions = set()

        for condition in conditions:
            key, value = condition.split("=")
            logger.debug(f"Adding constraint to set {key} condition as {value}")
            provided_conditions.add(key)
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

    def get_correct_case_principal(self, principal: str) -> str:
        identities = [x.lstrip("identity_") for x in self.model_vars if x.startswith("identity_arn")]

        for identity in identities:
            if identity.lower() == principal.lower():
                return identity

        raise Exception("Identity not found to match principal")

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
                solver.add(s != source)
                sat = solver.check() == z3.sat
                yield self.get_correct_case_principal(str(source)[1:-1])

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
