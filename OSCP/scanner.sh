#!/bin/bash
 
target="$1"
outfile="$2"
 
nmap -A -Pn -sCV -p$(
    rustscan -a "$target" 2>/dev/null |
    awk -F'[: ]+' '/Open/{print $3}' |
    paste -sd,
) "$target" | tee "$outfile"