include ../Makefile.kernel

res:
	make clean
	make

g:
	make res
	make grade
tes:
	make res
	pintos -v -k -T 300 --qemu --filesys-size=2 -p build/tests/vm/page-linear -a page-linear --swap-size=4 -- -q -f run page-linear
ges:
	make res
	pintos -v -k -T 60 --qemu --filesys-size=2 -p build/tests/userprog/read-boundary -a read-boundary -p ../tests/userprog/sample.txt -a sample.txt --swap-size=4 -- -q -f run read-boundary
