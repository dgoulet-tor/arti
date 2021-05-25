#!/bin/sh

cargo tarpaulin -o Html --all-features --output-dir coverage/ --ignore-tests
