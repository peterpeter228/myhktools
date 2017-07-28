#!/bin/bash
echo sh getDomainInfo.sh 360.com
echo whois $1
whois $1
echo
echo host -a $1
host -a $1
echo 
echo dig $1 any
dig $1 any
echo 
echo dnsenum $1
dnsenum $1
echo
echo dnsdict6 -4 -d $1
dnsdict6 -4 -d $1
echo
echo fierce -dns $1 -threads 3
fierce -dns $1 -threads 3
echo
echo dmitry -winse $1
dmitry -winse $1
echo
echo dmitry -p $1 -f -b
dmitry -p $1 -f -b
echo
echo theharvester -d $1 -l 100 -b bing
theharvester -d $1 -l 100 -b bing
echo
echo theharvester -d $1 -l 100 -b  linkedin
theharvester -d $1 -l 100 -b  linkedin
echo
echo metagoofil -d $1 -l 20 -t doc,pdf,ppt,xls,xlsx,docx,pptx -n 5  -f $1.html -o $1
metagoofil -d $1 -l 20 -t doc,pdf,ppt,xls,xlsx,docx,pptx -n 5  -f $1.html -o $1

