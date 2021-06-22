#!/usr/bin/python

import sys
import os
import re
import shutil

PAT = re.compile(r'^#!\[(allow|deny|warn)')

WANT_LINTS = """
#![deny(missing_docs)]
#![warn(noop_method_call)]
#![deny(unreachable_pub)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::cargo_common_metadata)]
#![deny(clippy::debug_assert_with_mut_call)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::exhaustive_structs)]
#![deny(clippy::expl_impl_clone_on_copy)]
#![deny(clippy::fallible_impl_from)]
#![deny(clippy::large_stack_arrays)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::clone_on_ref_ptr)]
#![warn(clippy::cognitive_complexity)]
#![warn(clippy::manual_ok_or)]
#![warn(clippy::needless_borrow)]
#![warn(clippy::option_option)]
#![warn(clippy::rc_buffer)]
#![warn(clippy::trait_duplication_in_bounds)]
#![warn(clippy::unseparated_literal_suffix)]
"""
WANT_LINTS = [ "%s\n" % w for w in WANT_LINTS.split() ]

SOON="""
#![deny(clippy::pub_enum_variant_names)]
#![deny(clippy::future_not_send)]
#![deny(clippy::redundant_closure_for_method_calls)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]
#![deny(clippy::expect_used)]
#![deny(clippy::checked_conversions)]
#![warn(clippy::needless_pass_by_value)]
#![deny(clippy::unnecessary_wraps)]
#![deny(clippy::if_then_some_else_none)]
#![deny(clippy::implicit_clone)]
#![deny(missing_debug_implementations)]
#![deny(unused_crate_dependencies)]
"""

DECIDED_NOT = """
#![deny(clippy::redundant_pub_crate)]
"""


PAT2 = re.compile(r'^#!\[(allow|deny|warn)\(((?:clippy::)?)([^\)]*)')
def warning_key(w):
    m = PAT2.match(w)
    return (len(m.group(2)), m.group(3))

def filter_file(lints, inp, outp):
    head,warnings,other = list(),list(),list()
    for line in inp.readlines():
        if line.startswith("//!"):
            head.append(line)
        elif PAT.match(line) :
            warnings.append(line)
        else:
            other.append(line)

    for add_lint in lints:
        if add_lint not in warnings:
            warnings.append(add_lint)
    warnings.sort(key=warning_key)

    while other[0] == '\n':
        del other[0]

    for line in head:
        outp.write(line)
    outp.write("\n")
    for line in warnings:
        outp.write(line)
    outp.write("\n")
    for line in other:
        outp.write(line)

def process(lints, fn):
    print("{}...".format(fn))
    bak_name = fn+".bak"
    outp = open(bak_name,'w')
    inp = open(fn,'r')
    filter_file(lints, inp, outp)
    inp.close()
    outp.close()
    shutil.move(bak_name, fn)

def main(lints,files):
    if not os.path.exists("./tor-proto/src/lib.rs"):
        print("Run this from the top level of an arti repo.")
        sys.exit(1)

    for fn in files:
        process(lints, fn)


if __name__ == '__main__':
    main(WANT_LINTS, sys.argv[1:])
