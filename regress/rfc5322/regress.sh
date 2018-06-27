set -e

for f in tests/valid*.txt; do
	echo "===> $f"
	out=/tmp/$(basename $f).dup
	./dup $f > $out
	diff -u $f $out

	echo "===> $f (bufferize)"
	./dup -b $f > $out
	diff -u $f $out
done

echo "dup: parse error: Inappropriate file type or format" > /tmp/err
for f in tests/broken*.txt; do
	echo "===> $f"
	out=/tmp/$(basename $f).err
	set +e
	./dup $f > /dev/null 2> $out
	set -e
	diff -u /tmp/err $out

	echo "===> $f (bufferize)"
	set +e
	./dup -b $f > /dev/null 2> $out
	set -e
	diff -u /tmp/err $out
done

for f in tests/*.mbox; do
	echo "===> $f"
	out=/tmp/$(basename $f).dup
	./dup -m $f > $out
	diff -u $f $out

	echo "===> $f (bufferize)"
	./dup -b -m $f > $out
	diff -u $f $out
done
