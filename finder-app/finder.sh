echo "Finder script started"
filesdir=$1
searchstr=$2
echo "input filesdir:${filesdir} searchstr:${searchstr}"
if [ $# -lt 1 ]
then
echo "filesdir and  searchstr was not specified!"
exit 1
elif [ $# -lt 2 ]
then
"searchstr was not specified!"
exit 1
fi
if [ ! -d $filesdir ]
then
echo "${filesdir} is not a directory!"
exit 1
fi
X=$(ls -1 "$filesdir" | wc -l)
Y=$(grep -R "$searchstr" "$filesdir" | wc -l)
echo "The number of files are ${X} and the number of matching lines are ${Y}"
exit 0
