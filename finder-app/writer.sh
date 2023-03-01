if [ $# -lt 1 ]
then
echo "writefile and  writestr was not specified!"
exit 1
elif [ $# -lt 2 ]
then
"searchstr was not specified!"
exit 1
fi
writefile=$1
writestr=$2
if [ -d $writefile ]
then
echo "${writefile} is not a file!"
exit 1
fi
mkdir -p "$(dirname "$writefile")"
echo "${writestr}" > $writefile
