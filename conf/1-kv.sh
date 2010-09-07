echo 'obj-$(CONFIG_ATA_OVER_ETH)	+= 5.o' > conf/Makefile
if $make_cmd 2>&1 1> /dev/null \
	| grep 'initialization from incompatible pointer type' > /dev/null 2>&1; then
	echo new
else
	echo old
fi

