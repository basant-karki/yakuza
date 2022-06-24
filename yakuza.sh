#!/bin/bash
source ~/.profile #refreshment

while wget "https://raw.githubusercontent.com/basant-karki/yakuza/main/domains.txt"; do

finished_alert(){
	#call the function after finishing the task.
	clear 
	echo "All done mr.basant -Jarvis"
	exit
}

kxss_for_xss_scanner(){
	cat waybackdata/kxss_raw_urls.txt | kxss > waybackdata/kxss_suspected_urls.txt
	finished_alert
}

waybackdata_filters(){
	#mannually-check-http
	cat waybackdata/wayback-raw-data | grep =http > waybackdata/suspect-urls.txt
	#gf-patterns
	cat waybackdata/wayback-raw-data | gf aws-keys > waybackdata/aws-keys.txt
	cat waybackdata/wayback-raw-data | gf base64 > waybackdata/base64.txt
	cat waybackdata/wayback-raw-data | gf debug-pages > waybackdata/debug-pages.txt
	cat waybackdata/wayback-raw-data | gf debug_logic > waybackdata/debug_logic.txt
	cat waybackdata/wayback-raw-data | gf firebase > waybackdata/firebase.txt
	cat waybackdata/wayback-raw-data | gf fw > waybackdata/fw.txt
	cat waybackdata/wayback-raw-data | gf go-functions > waybackdata/go-functions.txt
	cat waybackdata/wayback-raw-data | gf http-auth > waybackdata/http-auth.txt
	cat waybackdata/wayback-raw-data | gf idor > waybackdata/idor.txt
	cat waybackdata/wayback-raw-data | gf img-traversal > waybackdata/img-traversal.txt
	cat waybackdata/wayback-raw-data | gf interestingEXT > waybackdata/interestingEXT.txt
	cat waybackdata/wayback-raw-data | gf interestingparams > waybackdata/interestingparams.txt
	cat waybackdata/wayback-raw-data | gf interestingsubs > waybackdata/interestingsubs.txt
	cat waybackdata/wayback-raw-data | gf ip > waybackdata/ip.txt
	cat waybackdata/wayback-raw-data | gf json-sec > waybackdata/json-sec.txt
	cat waybackdata/wayback-raw-data | gf jsvar > waybackdata/jsvar.txt
	cat waybackdata/wayback-raw-data | gf lfi > waybackdata/lfi.txt
	cat waybackdata/wayback-raw-data | gf meg-headers > waybackdata/meg-headers.txt
	cat waybackdata/wayback-raw-data | gf php-curl > waybackdata/php-curl.txt
	cat waybackdata/wayback-raw-data | gf php-errors > waybackdata/php-errors.txt
	cat waybackdata/wayback-raw-data | gf php-serialized > waybackdata/php-serialized.txt
	cat waybackdata/wayback-raw-data | gf php-sinks > waybackdata/php-sinks.txt
	cat waybackdata/wayback-raw-data | gf php-sources > waybackdata/php-sources.txt
	cat waybackdata/wayback-raw-data | gf rce > waybackdata/rce.txt
	cat waybackdata/wayback-raw-data | gf redirect > waybackdata/redirect.txt
	cat waybackdata/wayback-raw-data | gf s3-buckets > waybackdata/s3-buckets.txt
	cat waybackdata/wayback-raw-data | gf sec > waybackdata/sec.txt
	cat waybackdata/wayback-raw-data | gf servers > waybackdata/servers.txt
	cat waybackdata/wayback-raw-data | gf sqli > waybackdata/sqli.txt
	cat waybackdata/wayback-raw-data | gf ssti > waybackdata/ssti.txt
	cat waybackdata/wayback-raw-data | gf ssrf > waybackdata/ssrf.txt
	cat waybackdata/wayback-raw-data | gf strings > waybackdata/strings.txt
	cat waybackdata/wayback-raw-data | gf takeovers > waybackdata/takeovers.txt
	cat waybackdata/wayback-raw-data | gf upload-fields > waybackdata/upload-fields.txt
	cat waybackdata/wayback-raw-data | gf urls > waybackdata/urls.txt
	cat waybackdata/wayback-raw-data | gf xss > waybackdata/xss.txt
	#For_KXSS
	cat waybackdata/wayback-raw-data | grep -iE  = > waybackdata/equals2_urls.txt
	cat waybackdata/equals2_urls.txt | sed 's/=.*/=/' > waybackdata/waybackurls/kxss_raw_urls.txt
	kxss_for_xss_scanner
}


wayback_archive_hunting(){
	mkdir waybackdata
	cat subs.txt | gau --threads 2 --o waybackdata/wayback-raw-data.txt
	waybackdata_filters
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
