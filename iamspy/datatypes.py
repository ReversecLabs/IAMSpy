import logging
import base64
import ipaddress
import string
import z3
from dateutil.parser import parse

# equivalient to chars in string.ascii_letters + string.digits + string.punctuation
ANY = z3.Range("!", "~")

logger = logging.getLogger("iamspy.datatypes")


def convert(type, data, **kwargs):
    return _converters[type](data, **kwargs)


def parse_string(item, string, wildcard=True, case_sensitive=False):
    """
    Parsing strings to unpack wildcards, so that the end result is a set of
    components that are either regexes of strings or z3.Star() wildcard
    representations, to support wildcards in ARNs and permissions
    """
    # logger.debug(f"Parsing {item} as string: {string}")

    if wildcard:
        regex = _regex_parse_string(string, case_sensitive=case_sensitive)
    else:
        if case_sensitive:
            regex = z3.Re(string)
        else:
            regex = z3.Re(string.lower())

    return z3.InRe(item, regex)


def _regex_parse_string(string, case_sensitive=False):
    def intersperse(parts, char):
        output = [char] * (len(parts) * 2 - 1)
        output[0::2] = parts
        return output

    star_parts = intersperse(string.split("*"), "*")
    parts = []
    for part in star_parts:
        if "?" in part:
            question_split = intersperse(part.split("?"), "?")
            parts.extend(question_split)
        else:
            parts.append(part)

    regex_parts = []
    for part in parts:
        if part == "*":
            regex_parts.append(z3.Star(ANY))
        elif part == "?":
            regex_parts.append(ANY)
        else:
            if part == "" or case_sensitive:
                chars = z3.Re(part)
            else:
                chars = z3.Re(part.lower())
            regex_parts.append(chars)

    if len(regex_parts) == 1:
        regex = z3.simplify(regex_parts[0])
    else:
        regex = z3.simplify(z3.Concat(*regex_parts))

    return regex


def _arn(data):
    parts = data.split(":", 5)
    return [_regex_string(x) for x in parts]


def _bool(data):
    if "true" == str(data.lower()):
        return z3.BoolVal(True)
    elif "false" == str(data.lower()):
        return z3.BoolVal(False)
    else:
        raise TypeError(f"Invalid Bool: {data}")


def _date(data):
    return int(parse(data).timestamp())


def _numeric(data):
    if "." in str(data):
        return z3.RealVal(data)
    else:
        return z3.IntVal(data)


def _string(data):
    return z3.StringVal(data)


def _regex_string(data, case_sensitive=False):
    return _regex_parse_string(data, case_sensitive=case_sensitive)


def _ip(data):
    ip = ipaddress.ip_network(data, strict=False)
    return z3.BitVecVal(int(ip[0]), ip.max_prefixlen), z3.BitVecVal(int(ip.netmask), ip.max_prefixlen)


_converters = {
    "Arn": _arn,
    "Bool": _bool,
    "Date": _date,
    "Numeric": _numeric,
    "String": _string,
    "RegexString": _regex_string,
    "IpNetwork": _ip,
}
