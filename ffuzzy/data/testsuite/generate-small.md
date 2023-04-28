# Generator Tests

## `generate-small.ssdeep.txt` format

| Column | Description                                                            |
| ------ | ---------------------------------------------------------------------- |
| `$1`   | File name (relative to the top source directory of this crate)         |
| `$2`   | Flags indicating which test should be performed and certain properties |
| `$3`   | Expected fuzzy hash value                                              |

### Flags

| Flag | Description                                                                             |
| ---- | --------------------------------------------------------------------------------------- |
| `01` | Truncated short fuzzy hash                                                              |
| `02` | Non-truncated long fuzzy hash                                                           |
| `04` | Fuzzy hash must be normalized to perform the test                                       |
| `08` | Before normalization, the original fuzzy hash could not be stored in a short fuzzy hash |



## Test Files

### `hello-world-N.txt`

| Filename Part | Description                                        |
| ------------- | -------------------------------------------------- |
| `N`           | Trailing bytes (`0`: none, `1`: `\n`, `2`: `\r\n`) |

This is "Hello, World!" test vectors.


### `nopiece-behavior-1-NN.bin`

| Filename Part | Description                                                       |
| ------------- | ----------------------------------------------------------------- |
| `NN`          | Two digits between `01` and `14` representing the final file size |

Those files will not trigger any piece splitting (at all) and all except
14 bytes `nopiece-behavior-14.bin` does not make the final rolling hash
value zero.


### `nopiece-behavior-2-RR.bin`

| Filename Part | Description                              |
| ------------- | ---------------------------------------- |
| `RR`          | Repetition number of `h_org == 0` pieces |

Those files will not trigger any piece splitting.  This is very similar to
`nopiece-behavior-1-NN.bin` except we use a specific pattern which satisfies
`h_org == 0` (the original rolling hash value of `0xffffffff`) after processing
the 7-byte pattern.


### `repeating-bhB-T-RR-addA.bin`

| Filename Part | Description                                                       |
| ------------- | ----------------------------------------------------------------- |
| `B`           | Either `1` or `2`.  Test case generated for specified block hash  |
| `T`           | Test type                                                         |
| `RR`          | Number of piece pattern repetition                                |
| `A`           | Added zero bytes at the tail (`0`, `1` or `7`)                    |

It tests interaction between the truncation, rolling hash-based current state
appendation (when rolling hash value is non-zero) and the normalization.

#### Test Types

| Test Type | Description                                                                                                                            |
| --------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `a`       | Regular (after repeating `SIZE_OF_BH` times; while added null bytes are `0` or `1`, block hash contains two or more unique characters) |
| `b`       | After repeating `SIZE_OF_BH-1` times and adding one null byte will make the block hash consist of identical characters                 |
| `c`       | After repeating `SIZE_OF_BH` times and adding one null byte will make the block hash consist of identical characters                   |


### `minfsz-TT-BB-DD.bin`

| Filename Part | Description                                                                                             |
| ------------- | ------------------------------------------------------------------------------------------------------- |
| `TT`          | Target (maximum) block hash index                                                                       |
| `BB`          | Base block hash index for given file size                                                               |
| `DD`          | File size diff relative to border size (`na` : `-2`, `nb` : `-1`, `nc` : `0`, `pa` : `+1`, `pb` : `+2`) |
| `A`           | Added zero bytes at the tail (`0`, `1` or `7`)                                                          |

It tests minimum file size for given block hash index.

If `BB` is less than `TT` and `DD` is either `pa` or `pb`, double block hash
relative to `BB` will be used.


### `trigger-blkhash-nonelim-T.bin`

| Filename Part | Description      |
| ------------- | ---------------- |
| `T`           | Test case number |

It tests when *not* to perform block hash elimination.

The primary purpose of this is to improve coverage.


### `trigger-lasthash.bin`

It triggers the "last hash" updates.

The primary purpose of this is to improve coverage.
