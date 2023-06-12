#!/bin/bash

sed 's/\t/,/g' "$1" | sed 's/ /,/g' | awk -F"," '{ if ($12 != 4) print $7, $8, $9, $10, $12}'
#sed 's/\t/,/g' "$1" | sed 's/ /,/g' | awk -F"," '{ if ($12 != 4 && !seen[$7$8]++) print $7, $8, $9, $10, $12; print $7}'
