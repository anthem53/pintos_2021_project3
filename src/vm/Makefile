include ../Makefile.kernel

res:
	make clean
	make

g:
	make res
	make grade
tes:
	make res
	pintos -v -k -T 60 --qemu --filesys-size=2 -p  build/tests/vm/mmap-write -a mmap-write --swap-size=4 -- -q -f run mmap-write
ges:
	make res
	pintos -v -k -T 60 --qemu --filesys-size=2 -p build/tests/vm/pt-grow-bad -a pt-grow-bad --swap-size=4 -- -q -f run pt-grow-bad
