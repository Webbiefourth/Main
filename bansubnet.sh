#!/bin/bash
log="/var/log/fail2ban.log"
limit=5
zgrep ".*fail2ban.actions.*NOTICE.*Ban" /var/log/fail2ban.log | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | awk -F '.' '{print $1"."$2"."$3}' | sort -u | while read line
do
 count=$(zgrep -c ".*fail2ban.actions.*NOTICE.*Ban.*${line}" `echo "${log}*"` | awk -F':' '{ sum+=$2} END {print sum}')
 if [ ${count} -ge ${limit} ]
   then
     echo "ip subnet: ${line} appeared: ${count} time(s) which is greater than limit: ${limit}"
     if [ `/sbin/iptables -S | grep "${line}.0/24" | grep -c DROP` -eq 0 ]
       then
         /sbin/iptables -A INPUT -s ${line}.0/24 -j DROP
         log_entry="Permanently blocked subnet ${line}.0/24 from `geoiplookup ${line}.0 | awk -F',' '{print $NF}' | sed 's/^ //g'` after ${count} attacks"
         echo "${log_entry}"
         logger "${log_entry}"
       else
         log_entry="subnet ${line}.0/24 from `geoiplookup ${line}.0 | awk -F',' '{print $NF}' | sed 's/^ //g'` after ${count} attacks is already blocked. No action."
         echo "${log_entry}"
     fi
   else
     echo "ip subnet: ${line} appeared: ${count} time(s) -- less than blocking limit. Watching!"
 fi
done
/sbin/service iptables save
