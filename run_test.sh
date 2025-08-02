#! /bin/bash

cd tests
cargo bloat --release --filter f_miniscript
cargo run
cd ..