#!/bin/bash

# Script that audits CIS Security benchmarks

# Joe Thetford

function audit() {

	# Arg1: Name of policy
	# Arg2: Output expected for system in compliance
	# Arg3: The command to audit the policy
	# Arg4: Remediation measures

	if [[ $2 != $3 ]]
	then

		echo -e "\e[1;31mThe $1 policy is not in compliance. Current Value: $3\nRemediation:\n$4/e[0m"

	else

		echo -e "\e[;32mThe $1 policy is in Compliance. Current Value: $3\e[0m"

	fi
	echo""
}

while IFS=',' read -r f1 f2 f3 f4
do

	cmd=$(eval $f3)
	audit "${f1}" "${f2}" "${cmd}" "${f4}"
done < CentOS8Benchmark.csv
