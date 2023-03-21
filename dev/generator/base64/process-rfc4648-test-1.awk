# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: Copyright (C) 2023 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.

BEGIN {
    PRINT_NEXT = 0;
}

/Table 1: The Base 64 Alphabet/ {
    PRINT_NEXT = 1;
    PENDING_LINES = 3;
}

{
    if (PRINT_NEXT == 1)
    {
        if (PENDING_LINES == 0)
        {
            for (i = 1; i <= NF; i += 2)
            {
                if ($i == "(pad)")
                    continue;
                j = i + 1;
                print $i, $j;
            }
        }
        else
        {
            PENDING_LINES -= 1;
        }
    }
}

/^$/ {
    if (PRINT_NEXT == 1 && PENDING_LINES == 0)
    {
        PRINT_NEXT = 0;
    }
}
