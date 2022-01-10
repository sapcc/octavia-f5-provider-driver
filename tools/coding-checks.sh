#!/bin/sh
# This script is copied from octavia and adapted for octavia-f5-provider.
set -eu

usage () {
    echo "Usage: $0 [OPTION]..."
    echo "Run octavia's coding check(s)"
    echo ""
    echo "  -Y, --pylint [<basecommit>] Run pylint check on the entire octavia module or just files changed in basecommit (e.g. HEAD~1)"
    echo "  -h, --help                  Print this usage message"
    echo
    exit 0
}

join_args() {
    if [ -z "$scriptargs" ]; then
        scriptargs="$opt"
    else
        scriptargs="$scriptargs $opt"
    fi
}

process_options () {
    i=1
    while [ $i -le $# ]; do
        eval opt=\$$i
        case $opt in
            -h|--help) usage;;
            -Y|--pylint) pylint=1;;
            *) join_args;;
        esac
        i=$((i+1))
    done
}

run_pylint () {
    local target="${scriptargs:-all}"

    if [ "$target" = "all" ]; then
        files="octavia_f5"
    else
        case "$target" in
            *HEAD~[0-9]*) files=$(git diff --diff-filter=AM --name-only $target -- "*.py");;
            *) echo "$target is an unrecognized basecommit"; exit 1;;
        esac
    fi

    echo "Running pylint..."
    echo "You can speed this up by running it on 'HEAD~[0-9]' (e.g. HEAD~1, this change only)..."
    if [ -n "${files}" ]; then
        pylint -j 0 --max-nested-blocks 7 --extension-pkg-whitelist netifaces --rcfile=.pylintrc --output-format=colorized ${files}
    else
        echo "No python changes in this commit, pylint check not required."
        exit 0
    fi
}

scriptargs=
pylint=1

process_options $@

if [ $pylint -eq 1 ]; then
    run_pylint
    exit 0
fi
