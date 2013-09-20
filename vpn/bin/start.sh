#!/bin/sh
#
# Add this file to crontab to start vpn at boot:
# @reboot /home/vpn/vpn/bin/vpn.sh

PROJDIR=$HOME/vpn/vpn
PIDFILE="$PROJDIR/vpn.pid"
SOCKET="$PROJDIR/vpn.sock"
#OUTLOG="$PROJDIR/logs/access.log"
#ERRLOG="$PROJDIR/logs/error.log"

cd $PROJDIR
if [ -f $PIDFILE ]; then
    kill `cat -- $PIDFILE`
    rm -f -- $PIDFILE
fi

/usr/bin/env - \
  PYTHONPATH="../python:.." \
  ./manage.py runfcgi --settings=vpn.settings socket=$SOCKET pidfile=$PIDFILE outlog=$OUTLOG errlog=$ERRLOG workdir=$PROJDIR

chmod a+w $SOCKET
