#! /bin/sh
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: Copyright (C) 2023–2025 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.
if test ! -f rfc4648.txt; then
    echo "ERROR: rfc4648.txt not found." 1>&2
    echo "You may download RFC 4648 text file (rfc4648.txt) by for instance:" 1>&2
    echo "                   wget https://www.rfc-editor.org/rfc/rfc4648.txt" 1>&2
    exit 1
fi
PREV_N=-1
printf '%s\n%s' '    assert_base64_cases! {' '        ['
cat rfc4648.txt |
    awk -f process-rfc4648-test-1.awk |
    sort -n -k 1,1 |
    while read N CH; do
        # Check that all alphabet values are continuous from 0
        # (starts from 0 and continue like 1, 2, 3...)
        if test $(expr $PREV_N + 1) -ne $N; then
            printf '@ERROR@'
            break
        fi
        # New line if necessary.
        case "$CH" in
        [AOao0+])
            printf '\n           '
            ;;
        esac
        # Print test case.
        printf " b'%s'," "$CH"
        # Prepare for the next alphabet.
        PREV_N=$N
    done
printf '\n%s\n%s\n' '        ]' '    }'
