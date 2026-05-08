#!/usr/bin/env python3
"""Convert ENTITY-MIB snmpwalk output to lshw-like tree format.

Reads from stdin or file argument and prints a tree showing the physical
containment hierarchy with key attributes (description, class, vendor,
product, serial, etc.).
"""

import sys
import re
import argparse
from collections import defaultdict


CLASS_NAMES = {
    1: "other", 2: "unknown", 3: "chassis", 4: "backplane",
    5: "container", 6: "powerSupply", 7: "fan", 8: "sensor",
    9: "module", 10: "port", 11: "stack", 12: "cpu",
    13: "energyObject", 14: "battery", 15: "storageDrive",
}


ATTRIBUTES = (
    ('Descr', 'description'),
    ('VendorType', 'vendor-type'),
    ('ParentRelPos', 'parent-relative-position'),
    ('HardwareRev', 'hardware-revision'),
    ('FirmwareRev', 'firmware-revision'),
    ('SoftwareRev', 'software-revision'),
    ('SerialNum', 'serial'),
    ('MfgName', 'manufacturer'),
    ('ModelName', 'model'),
    ('Alias', 'alias'),
    ('AssetID', 'asset-id'),
    ('IsFRU', 'is-fru'),
    ('MfgDate', 'manufacturing-date'),
    ('Uris', 'uris'),
    ('UUID', 'uuid'),
)


def parse_snmp_file(lines):
    """Parse snmpwalk lines into dict of index -> {attr -> value}."""
    entities = {}
    pattern = re.compile(r'^ENTITY-MIB::entPhysical(\w+)\.(\d+) = [^:]+: (.+)$')
    alias_pattern = re.compile(
        r'^ENTITY-MIB::entAliasMappingIdentifier\.(\d+)\.(\d+) = OID: (.+)$'
    )
    for line in lines:
        line = line.strip()
        m = alias_pattern.match(line)
        if m:
            idx, logical_idx, val = int(m.group(1)), int(m.group(2)), m.group(3).strip()
            if idx not in entities:
                entities[idx] = {}
            entities[idx].setdefault('AliasMappings', []).append((logical_idx, val))
            continue

        m = pattern.match(line)
        if not m:
            continue
        attr, idx, val = m.group(1), int(m.group(2)), m.group(3).strip()
        if idx not in entities:
            entities[idx] = {}
        entities[idx][attr] = val
    return entities


def build_tree(entities):
    """Build parent->children mapping from entPhysicalContainedIn."""
    children = defaultdict(list)
    roots = []
    for idx, attrs in sorted(entities.items()):
        parent = int(attrs.get('ContainedIn', 0))
        children[parent].append(idx)
        if parent == 0:
            roots.append(idx)
    return children, roots


def class_prefix(cls_val):
    """Return the lshw-style prefix for a class."""
    # Handle format like "chassis(3)" or just integer
    if isinstance(cls_val, int):
        name = CLASS_NAMES.get(cls_val, "unknown")
    else:
        m = re.search(r'\((\d+)\)', str(cls_val))
        if m:
            name = CLASS_NAMES.get(int(m.group(1)), "unknown")
        else:
            name = str(cls_val)
    return name


def print_tree(entities, children, parent_idx, hidden_attrs=None, prefix=''):
    """Recursively print the entity tree with proper tree structure."""
    hidden_attrs = hidden_attrs or set()
    child_list = sorted(children.get(parent_idx, []))
    for i, idx in enumerate(child_list):
        is_last = (i == len(child_list) - 1)
        e = entities[idx]
        name = e.get('Name', '')
        model = e.get('ModelName', '')
        descr = e.get('Descr', '')
        header_attrs = set()

        cls_name = class_prefix(e.get('Class', ''))
        connector = '└── ' if is_last else '├── '
        header = f"{prefix}{connector}[{idx}:{cls_name}]"
        if model:
            header += f" {model}"
            header_attrs.add('ModelName')
            if name:
                header += f" ({name})"
        elif name:
            header += f" {name}"
        elif descr:
            header += f" {descr}"
            header_attrs.add('Descr')
        print(header)

        spacer = '    ' if is_last else '│   '
        child_prefix = prefix + spacer
        attr_indent = prefix + ('│   ' if not is_last else '    ')
        for attr, label in ATTRIBUTES:
            if attr in hidden_attrs or attr in header_attrs:
                continue
            value = e.get(attr, '')
            if value:
                print(f"{attr_indent}{label}: {value}")
        for logical_idx, value in sorted(e.get('AliasMappings', [])):
            if logical_idx:
                print(f"{attr_indent}alias-mapping[{logical_idx}]: {value}")
            else:
                print(f"{attr_indent}alias-mapping: {value}")

        if children.get(idx):
            print(f"{child_prefix}│")
        else:
            print(attr_indent.rstrip())

        print_tree(entities, children, idx, hidden_attrs, child_prefix)


def main():
    parser = argparse.ArgumentParser(
        description="Convert ENTITY-MIB snmpwalk output to a tree."
    )
    parser.add_argument('file', nargs='?', help="snmpwalk input file")
    parser.add_argument('--hide-serial', action='store_true',
                        help="hide entPhysicalSerialNum values")
    parser.add_argument('--hide-uuid', action='store_true',
                        help="hide entPhysicalUUID values")
    args = parser.parse_args()

    if args.file:
        with open(args.file) as f:
            lines = f.readlines()
    else:
        lines = sys.stdin.readlines()

    hidden_attrs = set()
    if args.hide_serial:
        hidden_attrs.add('SerialNum')
    if args.hide_uuid:
        hidden_attrs.add('UUID')

    entities = parse_snmp_file(lines)
    children, roots = build_tree(entities)
    print_tree(entities, children, 0, hidden_attrs)


if __name__ == '__main__':
    main()
