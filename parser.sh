#!/bin/bash

#declare file(s)
files=./*.ckl
output='date'.csv

#create initial output file
echo "host, stig, High_Open, High_Closed, High_Not_Reviewd, Medium_Open, Medium_Closed, Medium_Not_Reviewed, Low_Open, Low_Closed, Low_Not_Reviewed" >> $output

#loop to iterate through all files
for file in $files
do
echo "Processing $file"


#Capture system
host=$(xmllint --shell $file <<<'cat //CHECKLIST/ASSET/HOST_NAME/text()'|head -2 |tail -1)

#Capture STIG
stig=$(xmllint --shell $file <<<'cat /CHECKLIST/STIGS/iSTIG/STIG_INFO/SI_DATA[4]/SID_DATA/text()'|head -2 |tail -1)

#RAW Numbers (need to break this down per Category)
declare -i check1=$(xmllint --shell $file <<<'cat /*/*/*/*/STATUS/text()' |grep NotAFinding | wc -l)
declare -i check2=$(xmllint --shell $file <<<'cat /*/*/*/*/STATUS/text()' |grep Open | wc -l)
declare -i check3=$(xmllint --shell $file <<<'cat /*/*/*/*/STATUS/text()' |grep Not_Reviewed | wc -l)


#get total vulnerability count
#echo "$((check1 + check2 + check3))"

#total CAT I
declare -i tCatI=$(xmllint --shell $file <<<'cat /*/*/*/*/*/ATTRIBUTE_DATA'|grep '>high<'|wc -l)

#total CAT II
declare -i tCatII=$(xmllint --shell $file <<<'cat /*/*/*/*/*/ATTRIBUTE_DATA'|grep '>medium<'|wc -l)

#total CAT III
declare -i tCatIII=$(xmllint --shell $file <<<'cat /*/*/*/*/*/ATTRIBUTE_DATA'|grep '>low<'|wc -l)

#echo "Cat I Findings   = "$tCatI
#echo "Cat II Findings  = "$tCatII
#echo "Cat III Findings = "$tCatIII

declare -i hOpen=0
declare -i hClosed=0
declare -i hNR=0
declare -i mOpen=0
declare -i mClosed=0
declare -i mNR=0
declare -i lOpen=0
declare -i lClosed=0
declare -i lNR=0

count=$(xmllint --xpath "count(//CHECKLIST/STIGS/iSTIG/VULN)" $file)

for((i=1;$i<=$count;i++)) ; do
        category=$(xmllint --shell $file <<<"cat /CHECKLIST/STIGS/iSTIG/VULN[$i]/STIG_DATA[2]/ATTRIBUTE_DATA/text()")
        stat=$(xmllint --shell $file <<<"cat /CHECKLIST/STIGS/iSTIG/VULN[$i]/STATUS/text()")
	if [[ $category = *"high"* ]] ; then
		if [[ $stat = *"Open"* ]]; then
			hOpen=$((hOpen + 1));
		fi
		if [[ $stat = *"NotAFinding"* ]]; then
			hClosed=$((hClosed + 1));
		fi
		if [[ $stat = *"Not_Reviewed"* ]]; then
			hNR=$((hNR + 1));
		fi
	fi
	if [[ $category = *"medium"* ]] ; then
		if [[ $stat = *"Open"* ]]; then
			mOpen=$((mOpen + 1));
		fi
		if [[ $stat = *"NotAFinding"* ]]; then
			mClosed=$((mClosed + 1));
		fi
		if [[ $stat = *"Not_Reviewed"* ]]; then
			mNR=$((mNR + 1));
		fi
	fi
	if [[ $category = *"low"* ]] ; then
		if [[ $stat = *"Open"* ]]; then
			lOpen=$((lOpen + 1));
		fi
		if [[ $stat = *"NotAFinding"* ]]; then
			lClosed=$((lClosed + 1));
		fi
		if [[ $stat = *"Not_Reviewed"* ]]; then
			lNR=$((lNR + 1));
		fi
	fi
done

echo "$host, $stig, $hOpen, $hClosed, $hNR, $mOpen, $mClosed, $mNR, $lOpen, $lClosed, $lNR" >> $output
done

## This section creates totals for LibreCalc.  Not sure if it works in excel

# figure out how many files you are working with
declare -i fNum=$(ls -l *.ckl | wc -l)

# Insert summaries line into csv
echo "," >> $output
echo ",Totals:,=SUM(C2:C$((fNum + 1))),=SUM(D2:D$((fNum + 1))),=SUM(E2:E$((fNum + 1))),=SUM(F2:F$((fNum + 1))),=SUM(G2:G$((fNum + 1))),=SUM(H2:H$((fNum + 1))),=SUM(I2:I$((fNum + 1))),=SUM(J2:J$((fNum + 1))),=SUM(K2:K$((fNum + 1)))" >> $output

