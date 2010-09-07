# This script is run from its parent directory.

driver_d=$1
shift
make_cmd="$*"

export driver_d make_cmd

me=`basename $0`

set -e

i=1
while test -r conf/$i-kv.sh; do
	printf "$i "
	kv=`sh conf/$i-kv.sh`
	av=`sh conf/$i-av.sh`

	case "$kv" in
		"new")
			test "$av" = "old" && {
				echo
				patch -p1 < conf/$i.diff
			}
			;;
		"old")
			test "$av" = "old" || {
				echo
				patch -p1 -R < conf/$i.diff
			}
			;;
		*)
			echo "usage: $me {new|old}" 1>&2
			exit 1
			;;
	esac
	i=`expr $i + 1`
done

echo ok
exit 0
