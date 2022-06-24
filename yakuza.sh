#!/bin/bash

source ~/.profile #refreshment

while wget "https://raw.githubusercontent.com/basant-karki/yakuza/main/domains.txt"; do

finished_alert(){
	echo "All done" 
}

wayback_archive_hunting(){
	cat subs.txt | gau --threads 5 --o wayback-raw-data.txt
	finished_alert
}

subdomains_enumeration_and_resolve-m(){

	findomain -f wild.txt --http-status -u wild-subs.txt -q
	cat single.txt | httprobe > single-live.txt
	cat single-live.txt > subs.txt
	cat wild-subs.txt > subs.txt
	rm -fr single.txt single-live.txt wild.txt wild-temp.txt wild-subs.txt domains.txt
	wayback_archive_hunting
}

wildcard_domain_management(){
	cat domains.txt | grep "*" > wild-temp.txt # Save only the domains which are in the wildcard
	cat domains.txt | grep -v "*" > single.txt # Save only the single domains
	sed 's/..//' wild-temp.txt > wild.txt
	subdomains_enumeration_and_resolve-m
}

wildcard_domain_management # calling domain for domain mamagement
	exit
done
