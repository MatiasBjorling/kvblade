echo 'obj-$(CONFIG_KVBLADE)	+= 3.o' > conf/Makefile
if $make_cmd 2>&1 1> /dev/null \
	  | grep 'redeclaration.*ATA_IDNF' > /dev/null 2>&1; then
	echo new
else
	echo old
fi
