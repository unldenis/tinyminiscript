#! /bin/bash

cd tests
# cargo bloat --release --filter tinyminiscript
clear
RUSTFLAGS=-Awarnings cargo run
cd ..