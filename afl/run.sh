cargo afl build

AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_SKIP_CPUFREQ=true cargo afl fuzz -i in -o out target/debug/afl