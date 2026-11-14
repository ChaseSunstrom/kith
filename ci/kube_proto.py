#!/usr/bin/env python3
"""The table kithd reads Kubernetes's binary encoding by (crates/kithd/src/kubeproto.txt),
made from the Go types Kubernetes itself is made from.

    python3 ci/kube_proto.py            # write the table
    python3 ci/kube_proto.py --check    # say whether the table in the tree is this one

`kubectl create` and Helm send the kinds Kubernetes has built in as protobuf. Each field
of a message is a number there; its name, what it holds, and whether Kubernetes leaves it
out of the JSON when it is empty are in the `json` and `protobuf` tags of the Go types
(types.go of each API group), which is all that is read here. The files are fetched once,
as the tag below has them, and must be the files whose hashes are written here.

The table, a message at a time:

    =Name
    NUMBER name TYPE

TYPE: s text, i a whole number, b true or false, y bytes, or a message's name; `*` before
it for a list, `{` for a mapping from text; `!` after it where an empty value is left out
(a field Go holds by value and marks `omitempty`). A name of `.` is a message whose fields
are its parent's in JSON. The status of each kind and who manages which field are left
out: kithd takes neither from a client.
"""

import hashlib
import os
import re
import sys
import urllib.request

TAG = "v0.37.2"
# (package, where it is, sha256)
FILES = [
    ("core", "kubernetes/api/%s/core/v1/types.go", "64b70c914fe25eba63bfb325401a551bbd0871e37eb7fd9b9878283a53e6e062"),
    ("apps", "kubernetes/api/%s/apps/v1/types.go", "953efbff73f7a40f48fe6b726be9d2a7ef87d3d0d2d01393d4e7fb309818e192"),
    ("batch", "kubernetes/api/%s/batch/v1/types.go", "165d6a77fbc43a81dd31a2efe8f5e1d3daa22ad921e273f9595fadbcc4468d1f"),
    ("networking", "kubernetes/api/%s/networking/v1/types.go", "161d7058ea5c7790775bc7f4b98fd962fbb06dc6261099f1222b21bc278c859c"),
    ("policy", "kubernetes/api/%s/policy/v1/types.go", "84a8c11cfc137cafabdc0c5546c1c9ede8f9a7a8a86ccf1ecf1be6afa5081aa4"),
    ("rbac", "kubernetes/api/%s/rbac/v1/types.go", "023c6b6f806f680f7d3dbffebdd26e3ed8c4c863701dac69ec0ea136b20ec4b2"),
    ("meta", "kubernetes/apimachinery/%s/pkg/apis/meta/v1/types.go", "a544ea7354cf745449e42db03a512f505aea91dc4adcdc79d6e656406066ebc6"),
]
# What a client may send whole: the kinds kithd's Kubernetes paths take, and what goes with a delete.
ROOTS = [
    ("core", "Namespace"), ("core", "ConfigMap"), ("core", "Secret"), ("core", "ServiceAccount"),
    ("core", "Service"), ("core", "PersistentVolumeClaim"), ("apps", "Deployment"),
    ("apps", "StatefulSet"), ("apps", "DaemonSet"), ("batch", "Job"), ("batch", "CronJob"),
    ("networking", "Ingress"), ("networking", "IngressClass"), ("policy", "PodDisruptionBudget"),
    ("rbac", "Role"), ("rbac", "RoleBinding"), ("rbac", "ClusterRole"), ("rbac", "ClusterRoleBinding"),
    ("meta", "DeleteOptions"),
]
# How one package names another, and the types that are read by a rule of their own.
PACKAGES = {"metav1": "meta", "v1": "core", "corev1": "core", "apiv1": "core"}
SPECIAL = {
    "metav1.Time": "Time", "metav1.MicroTime": "Time", "metav1.Duration": "Duration",
    "resource.Quantity": "Quantity", "intstr.IntOrString": "IntOrString",
    "runtime.RawExtension": "RawExtension", "types.UID": "s", "types.NodeName": "s",
}
BASIC = {"string": "s", "bool": "b", "int": "i", "int32": "i", "int64": "i", "uint32": "i", "uint64": "i"}
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TABLE = os.path.join(ROOT, "crates/kithd/src/kubeproto.txt")


def sources():
    cache = os.path.join(os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache"), "kith-kube", "types-" + TAG)
    os.makedirs(cache, exist_ok=True)
    for package, where, sha256 in FILES:
        path = os.path.join(cache, package + ".go")
        if not os.path.exists(path):
            repo, rest = (where % TAG).split("/", 2)[1], (where % TAG).split("/", 2)[2]
            url = "https://raw.githubusercontent.com/kubernetes/%s/%s" % (repo, rest)
            with urllib.request.urlopen(url, timeout=60) as answer:
                data = answer.read()
            with open(path, "wb") as out:
                out.write(data)
        with open(path, "rb") as file:
            data = file.read()
        if hashlib.sha256(data).hexdigest() != sha256:
            sys.exit("kube_proto.py: %s is not the file this script names (remove it to fetch it again)" % path)
        yield package, data.decode()


def parse(text):
    """The structs of a package (name -> fields) and its other named types (name -> what they are)."""
    structs, aliases, inside = {}, {}, None
    for line in text.splitlines():
        if inside is None:
            start = re.match(r"type (\w+) struct \{", line)
            alias = re.match(r"type (\w+) ([\w\.\*\[\]]+)\s*(//.*)?$", line)
            if start:
                inside = structs.setdefault(start.group(1), [])
            elif alias:
                aliases[alias.group(1)] = alias.group(2)
        elif line.startswith("}"):
            inside = None
        else:
            field = re.match(r"\s*(?:\w+\s+)?([\w\.\*\[\]]+)\s+`(.*)`", line)
            json = field and re.search(r'json:"([^"]*)"', field.group(2))
            proto = field and re.search(r'protobuf:"([^"]*)"', field.group(2))
            if json and proto:
                name, _, options = json.group(1).partition(",")
                inside.append((int(proto.group(1).split(",")[1]), name or ".", field.group(1), "omitempty" in options))
    return structs, aliases


def main():
    packages = {package: parse(text) for package, text in sources()}
    wanted, order, lines = list(ROOTS), [], {}

    def code(package, go):
        """A Go type as the table writes it, and whether Go holds it by value."""
        if go.startswith("*"):
            return code(package, go[1:])[0], False
        if go == "[]byte":
            return "y", False
        if go.startswith("[]"):
            return "*" + code(package, go[2:])[0], False
        if go.startswith("map["):
            return "{" + code(package, go[go.index("]") + 1:])[0], False
        if package == "meta" and "metav1." + go in SPECIAL:
            go = "metav1." + go
        if go in SPECIAL:
            return SPECIAL[go], SPECIAL[go] == "s"
        if go in BASIC:
            return BASIC[go], True
        if "." in go:
            prefix, go = go.split(".")
            if prefix not in PACKAGES:  # (a type of a group that is not read here: the field is left out)
                raise LookupError(prefix)
            package = PACKAGES[prefix]
        structs, aliases = packages[package]
        if go in aliases:
            return code(package, aliases[go])
        if go not in structs:
            sys.exit("kube_proto.py: %s.%s is neither a struct nor a name for something else" % (package, go))
        if (package, go) not in wanted:
            wanted.append((package, go))
        return go, False

    for package, name in wanted:  # (grows as it is read: every message a root leads to)
        if name in lines:
            sys.exit("kube_proto.py: two messages are called %s" % name)
        order.append(name)
        lines[name] = []
        for number, field, go, omitempty in sorted(packages[package][0][name]):
            if (field == "status" and (package, name) in ROOTS) or field == "managedFields":
                continue
            try:
                kind, by_value = code(package, go)
            except LookupError as unknown:
                print("kube_proto.py: left out: %s.%s (a %s of %s)" % (name, field, go, unknown), file=sys.stderr)
                continue
            lines[name].append("%d %s %s%s" % (number, field, kind, "!" if kind in ("s", "i", "b") and by_value and omitempty else ""))
    table = "".join("=%s\n%s" % (name, "".join(line + "\n" for line in lines[name])) for name in order)
    if "--check" in sys.argv:
        with open(TABLE) as file:
            if file.read() != table:
                sys.exit("kube_proto.py: %s is not what the types of %s give: run ci/kube_proto.py" % (TABLE, TAG))
        return print("kube_proto.py: ok: the table is what the types of %s give" % TAG)
    with open(TABLE, "w") as file:
        file.write(table)
    print("kube_proto.py: %s: %d messages, %d fields, %d bytes" % (TABLE, len(order), table.count("\n") - len(order), len(table)))


main()
