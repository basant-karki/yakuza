#!/bin/bash
source ~/.profile #refreshment

while true; do

finished_alert(){
	#call the function after finishing the task.
	echo "All done mr.basant -Jarvis"
	exit
}

kxss_for_xss_scanner(){
	echo "kxss_for_xss_scanner has started..."
	mkdir kxss
	cat waybackdata/kxss_raw_urls.txt | kxss > kxss/kxss_suspected_urls.txt
	clear
	finished_alert
}

waybackdata_filters(){
	echo "wayback_archive_filtering has started..."
	#mannually-check-http
	cat waybackdata/wayback-raw-data.txt | grep =http > waybackdata/suspect-urls.txt
	#gf-patterns
	cat waybackdata/wayback-raw-data.txt | gf aws-keys > waybackdata/aws-keys.txt
	cat waybackdata/wayback-raw-data.txt | gf base64 > waybackdata/base64.txt
	cat waybackdata/wayback-raw-data.txt | gf debug-pages > waybackdata/debug-pages.txt
	cat waybackdata/wayback-raw-data.txt | gf debug_logic > waybackdata/debug_logic.txt
	cat waybackdata/wayback-raw-data.txt | gf firebase > waybackdata/firebase.txt
	cat waybackdata/wayback-raw-data.txt | gf fw > waybackdata/fw.txt
	cat waybackdata/wayback-raw-data.txt | gf go-functions > waybackdata/go-functions.txt
	cat waybackdata/wayback-raw-data.txt | gf http-auth > waybackdata/http-auth.txt
	cat waybackdata/wayback-raw-data.txt | gf idor > waybackdata/idor.txt
	cat waybackdata/wayback-raw-data.txt | gf img-traversal > waybackdata/img-traversal.txt
	cat waybackdata/wayback-raw-data.txt | gf interestingEXT > waybackdata/interestingEXT.txt
	cat waybackdata/wayback-raw-data.txt | gf interestingparams > waybackdata/interestingparams.txt
	cat waybackdata/wayback-raw-data.txt | gf interestingsubs > waybackdata/interestingsubs.txt
	cat waybackdata/wayback-raw-data.txt | gf ip > waybackdata/ip.txt
	cat waybackdata/wayback-raw-data.txt | gf json-sec > waybackdata/json-sec.txt
	cat waybackdata/wayback-raw-data.txt | gf jsvar > waybackdata/jsvar.txt
	cat waybackdata/wayback-raw-data.txt | gf lfi > waybackdata/lfi.txt
	cat waybackdata/wayback-raw-data.txt | gf meg-headers > waybackdata/meg-headers.txt
	cat waybackdata/wayback-raw-data.txt | gf php-curl > waybackdata/php-curl.txt
	cat waybackdata/wayback-raw-data.txt | gf php-errors > waybackdata/php-errors.txt
	cat waybackdata/wayback-raw-data.txt | gf php-serialized > waybackdata/php-serialized.txt
	cat waybackdata/wayback-raw-data.txt | gf php-sinks > waybackdata/php-sinks.txt
	cat waybackdata/wayback-raw-data.txt | gf php-sources > waybackdata/php-sources.txt
	cat waybackdata/wayback-raw-data.txt | gf rce > waybackdata/rce.txt
	cat waybackdata/wayback-raw-data.txt | gf redirect > waybackdata/redirect.txt
	cat waybackdata/wayback-raw-data.txt | gf s3-buckets > waybackdata/s3-buckets.txt
	cat waybackdata/wayback-raw-data.txt | gf sec > waybackdata/sec.txt
	cat waybackdata/wayback-raw-data.txt | gf servers > waybackdata/servers.txt
	cat waybackdata/wayback-raw-data.txt | gf sqli > waybackdata/sqli.txt
	cat waybackdata/wayback-raw-data.txt | gf ssti > waybackdata/ssti.txt
	cat waybackdata/wayback-raw-data.txt | gf ssrf > waybackdata/ssrf.txt
	cat waybackdata/wayback-raw-data.txt | gf strings > waybackdata/strings.txt
	cat waybackdata/wayback-raw-data.txt | gf takeovers > waybackdata/takeovers.txt
	cat waybackdata/wayback-raw-data.txt | gf upload-fields > waybackdata/upload-fields.txt
	cat waybackdata/wayback-raw-data.txt | gf urls > waybackdata/urls.txt
	cat waybackdata/wayback-raw-data.txt | gf xss > waybackdata/xss.txt
	#For_KXSS
	cat waybackdata/wayback-raw-data.txt | grep -iE  = > waybackdata/equals2_urls.txt
	cat waybackdata/equals2_urls.txt | sed 's/=.*/=/' > waybackdata/waybackurls/kxss_raw_urls.txt
	clear
	kxss_for_xss_scanner
}


wayback_archive_hunting(){
	echo "wayback_archive_hunting has started..."
	mkdir waybackdata
	cat subs.txt | gau --threads 2 --o waybackdata/wayback-raw-data.txt
	clear
	waybackdata_filters
}

subdomains_enumeration_and_resolve-m(){

	echo "subdomains_enumeration_and_resolving has started......"
	echo "It can takes time depends upon your domain collection. So Please grab your coffee...."
	findomain -f wild.txt --http-status -u wild-subs.txt
	cat single.txt | httprobe > single-live.txt
	cat single-live.txt > subs.txt
	cat wild-subs.txt > subs.txt
	rm -fr single.txt single-live.txt wild.txt wild-temp.txt wild-subs.txt domains.txt
	clear
	wayback_archive_hunting
}

wildcard_domain_management(){
	echo "wildcard domain management started..."
	cat domains.txt | grep "*" > wild-temp.txt # Save only the domains which are in the wildcard
	cat domains.txt | grep -v "*" > single.txt # Save only the single domains
	sed 's/..//' wild-temp.txt > wild.txt
	clear
	subdomains_enumeration_and_resolve-m
}

	if find "domains.txt"; then
		wildcard_domain_management 	 # calling domain for domain mamagement
	else
		wget "http://bugera.000webhostapp.com/domains.txt" -q
		wildcard_domain_management 	 # calling domain for domain mamagement
	fi
	exit
done
