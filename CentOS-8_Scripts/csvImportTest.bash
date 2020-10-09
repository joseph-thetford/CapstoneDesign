#!/bin/bash

while read f1 f2 f3
do
	echo "OS is	: $f1"
	echo "Company is: $f2"
	echo "Value is	: $f3"
done < file.csv
