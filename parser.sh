#!/bin/bash

#declare file(s)
files=./*.ckl

for file in $files
do
echo "Processing $file"
#build 
#Capture system
xmllint --shell $file <<<'cat //CHECKLIST/ASSET/HOST_NAME/text()'|head -2 |tail -1


#Capture STIG
xmllint --shell $file <<<'cat /CHECKLIST/STIGS/iSTIG/STIG_INFO/SI_DATA[4]/SID_DATA/text()'|head -2 |tail -1

#RAW Numbers (need to break this down per Category)
declare -i check1=$(xmllint --shell $file <<<'cat /*/*/*/*/STATUS/text()' |grep NotAFinding | wc -l)
declare -i check2=$(xmllint --shell $file <<<'cat /*/*/*/*/STATUS/text()' |grep Open | wc -l)
declare -i check3=$(xmllint --shell $file <<<'cat /*/*/*/*/STATUS/text()' |grep Not_Reviewed | wc -l)


#get total vulnerability count
echo "$((check1 + check2 + check3))"

#total CAT I
declare -i tCatI=$(xmllint --shell $file <<<'cat /*/*/*/*/*/ATTRIBUTE_DATA'|grep '>high<'|wc -l)

#total CAT II
declare -i tCatII=$(xmllint --shell $file <<<'cat /*/*/*/*/*/ATTRIBUTE_DATA'|grep '>medium<'|wc -l)

#total CAT III
declare -i tCatIII=$(xmllint --shell $file <<<'cat /*/*/*/*/*/ATTRIBUTE_DATA'|grep '>low<'|wc -l)

echo "Cat I Findings   = "$tCatI
echo "Cat II Findings  = "$tCatII
echo "Cat III Findings = "$tCatIII

declare -i hOpen=0
declare -i hClosed=0
declare -i hNA=0
declare -i mOpen=0
declare -i mClosed=0
declare -i mNA=0
declare -i lOpen=0
declare -i lClosed=0
declare -i lNA=0

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
			hNA=$((hNA + 1));
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
			mNA=$((mNA + 1));
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
			lNA=$((lNA + 1));
		fi
	fi
done

echo $hOpen $hClosed $hNA
echo $mOpen $mClosed $mNA
echo $lOpen $lClosed $lNA
done

