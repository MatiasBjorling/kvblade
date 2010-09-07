f=kvblade.c
old="`grep 'ATA_IDNF =' $f`"
if test "$old"; then
	echo old
else
	echo new
fi
