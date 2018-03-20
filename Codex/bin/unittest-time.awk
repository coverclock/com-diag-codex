BEGIN			{ print "TEST,REAL,USER,SYS,BLOCKS,BLOCKSIZE,BYTES"; }
/^unittest/		{ TEST=$1; }
/^real\t/		{ REAL=$2; }
/^user\t/		{ USER=$2; }
/^sys\t/		{ SYS=$2; }
/^blocks\t/		{ BLOCKS=$2; }
/^blksize\t/		{ BLOCKSIZE=$2; }
/^bytes\t/		{ BYTES=$2; print TEST","REAL","USER","SYS","BLOCKS","BLOCKSIZE","BYTES; }
