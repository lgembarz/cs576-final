echo "input binary:"
read BINARY
echo "input payload:"
read PAYLOAD
./$BINARY < $PAYLOAD
