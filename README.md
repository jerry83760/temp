#!/bin/bash 
mkdir -p $1/subdomains 
mkdir -p $1/httpx 
mkdir -p $1/dnsx 
mkdir -p $1/naabu 
echo "####----Starting Amass----####" 
amass enum -passive -norecursive -noalts -d $1 > $1/subdomains/amass.txt 
echo "####----Starting Assetfinder----####" 
assetfinder --subs-only $1 > $1/subdomains/assetfinder.txt
echo "####----Starting Subfinder----####" 
subfinder -d $1 -o $1/subdomains/subfinder.txt 
curl -sk "https://crt.sh/?q=%.$1&output=json" | tr ',' '\n' | awk -F'"' '/name_value/ {gsub(/\*\./, "", $4); gsub(/\\n/,"\n",$4);print $4}' | tee -a $1/subdomains/crt_sh.txt 
curl -s "https://jldc.me/anubis/subdomains/$1" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u | tee -a $1/subdomains/jldc.txt 
curl -s -X POST -H "Content-Type: application/x-www-form-urlencoded" -d 'domain='$1'&submit=' https://seckrd.com/subdomain-finder.php | grep -oE "https?://[^'\"]+" | awk -F/ '{print $3}' | sort -u|tee -a $1/subdomains/seckrd.txt 
echo "####----Merging all Subdomains----####" 
cat $1/subdomains/* |sort -u |anew $1/subdomains/all.txt | tee $1/subdomains/new.txt 
echo "####----DNSX--------#####" 
cat $1/subdomains/new.txt | dnsx -a -resp-only |sort -u > $1/dnsx/dnsx.txt 
