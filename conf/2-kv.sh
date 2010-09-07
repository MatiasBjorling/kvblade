echo 'obj-$(CONFIG_KVBLADE)	+= 2.o' > conf/Makefile
if $make_cmd 2>&1 1> /dev/null \
	  | grep 'too many arguments to function.*skb_linearize' > /dev/null 2>&1; then
	echo new
else
	echo old
fi
