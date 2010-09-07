new="`grep '^rcv.*orig_dev' kvblade.c`"
if test "$new"; then
	echo new
else
	echo old
fi
