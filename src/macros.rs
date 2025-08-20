/// Output a string link to `bitcoin` source code.
#[macro_export]
macro_rules! bitcoin_definition_link {
    (
        $commit:literal, // Git commit hash
        $file_path:literal, // File path within `bitcoin`'s `src/`, e.g. `script/miniscript.h`
        $start:literal$(..=$end:literal)? // File lines, e.g. `0..=123` or `0`
    ) => {
        concat!(
            "Bitcoin Core [implementation](https://github.com/bitcoin/bitcoin/blob/",
            $commit,
            "/src/",
            $file_path,
            "#L",
            stringify!($start),
            $(
                "-L",
                stringify!($end),
            )?
            ")."
        )
    };
}
