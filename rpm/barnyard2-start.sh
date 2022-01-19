#!/bin/sh

if [ -f /etc/sysconfig/barnyard2 ]; then
	. /etc/sysconfig/barnyard2
fi

for INT in $INTERFACES; do
        ARCHIVEDIR="$SNORTDIR/$INT/archive"
        WALDO_FILE="$SNORTDIR/$INT/barnyard2.waldo"
        if [ ! -d /var/run/barnyard2-${INT} ]; then
                mkdir -p /var/run/barnyard2-${INT}
        fi
        BARNYARD_OPTS="-D -c $CONF -d $SNORTDIR/${INT} -w $WALDO_FILE -l $SNORTDIR/${INT} -a $ARCHIVEDIR -f $LOG_FILE -X /var/run/barnyard2-${INT}/barnyard.pid $EXTRA_ARGS --pid-path=/var/run/barnyard2-${INT}"
        /usr/bin/barnyard2 $BARNYARD_OPTS
	RETVAL=$?
done

exit $RETVAL

