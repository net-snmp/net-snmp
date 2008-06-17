:

cat <<-EXPLAIN

Convert use of ws2_32 to wsock32, and invoke winsock 1.x at WOSA startup.

This script will change the sources to use Winsock 1.
To complete the change, you must manually comment out all occurrences
of ws2tcpip.h.

If you decide later to undo these changes, you must do so manually.

If you do not type "y" in response to the next question,
this script will not make any change.

EXPLAIN

echo -n "Make irreversible change to use Winsock 1 ?[n] "
read ans
if [ "x$ans" != "xy" ] ; then
 echo
 echo "    Exiting without making changes."
 echo
 exit 0
fi

cd `dirname $0` ; HERE=`pwd`
cd ../..  # up from win32/dist


grep -rl ws2_32 . | grep -v tosock1.sh > xz
for aa in `cat xz` ; do
ed -s $aa <<-EOF
,s#ws2_32#wsock32#g
w
q
EOF
done
rm -f xz

grep -rl winsock2 . | grep -v tosock1.sh > xz
for aa in `cat xz` ; do
ed -s $aa <<-EOF
,s#winsock2#winsock#g
w
q
EOF
done
rm -f xz

ed -s snmplib/system.c <<-EOF
,s/MAKEWORD(2,2);/MAKEWORD(1,1);/g
w
q
EOF

exit 0
