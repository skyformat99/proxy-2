IP=`env | grep SSH_CLIENT | awk '{print $1;}' | cut -b 12-`


echo $IP >> ip_whitelist_3307.txt
echo $IP >> ip_whitelist_3308.txt

