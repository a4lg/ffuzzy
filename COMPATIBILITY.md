# Compatibility Policy against ssdeep / libfuzzy

## In General

Everything ssdeep / libfuzzy can generate (as an output) *and* can be accepted
back by ssdeep / libfuzzy is what we need to support on this project.

## Input

The input data which *must* be supported by this project must qualify:

1.  The input data is a valid output of ssdeep / libfuzzy functions
2.  Feeding the data back to ssdeep / libfuzzy does not cause the problems

On the other hand, this project may support an input data which does not
qualify those conditions, as long as supporting them will not cause serious
compatibility issues.

The input data which is *not* obligated to support in this project includes:

*   Invalid data (obviously)
*   Data which ssdeep / libfuzzy accepts *but*
    cannot be an output of ssdeep / libfuzzy
    *   e.g. a fuzzy hash prefixed by `'0'`  
             (the support for this kind of fuzzy hashes was removed
              in the version 0.2 of the `ffuzzy` crate)
    *   e.g. a fuzzy hash with long block hashes
             (which overflows the maximum block hash size in the raw form) but
             fits in after the normalization process  
             (this is currently supported by the `ffuzzy` crate as of
              the version 0.2 but we can remove the support anytime)
*   Data which is an output of ssdeep *but* feeding the data
    back to ssdeep causes serious errors / problems
    *   e.g. a CSV file output from ssdeep but input file names contain special
             characters that confuse the ssdeep's CSV file parser badly.
    *   On such cases, appropriate error handling / mitigation mechanism to
        minimize the data loss should be provided (as possible).

## Output

If a crate in this project generates something and it corresponds with a feature
in ssdeep / libfuzzy, it must qualify either:

1.  The output must be compatible with ssdeep / libfuzzy, version 2.14.1 or
2.  Explicitly stated as "incompatible with ssdeep / libfuzzy"  
    (separate methods or explicit configuration should be provided on such cases)
