#! /bin/sh
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: Copyright (C) 2023, 2024 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.
if test ! -f rfc4648.txt
then
    echo "ERROR: rfc4648.txt not found." 1>&2
    echo "You may download RFC 4648 text file (rfc4648.txt) by for instance:" 1>&2
    echo "                   wget https://www.rfc-editor.org/rfc/rfc4648.txt" 1>&2
    exit 1
fi
cat rfc4648.txt \
    | awk -f process-rfc4648-test-1.awk \
    | sort -n -k 1 \
    | awk '{printf("    assert_base64!(%d, b'"'"'%s'"'"');\n", $1, $2);}'
