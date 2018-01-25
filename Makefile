# No stack protector (nsp) and also executable stack (no NX)
fs_nsp_nnx: server.c
	gcc -fno-stack-protector -g -z execstack -o fs_nsp_nnx server.c 

# Executable stack (no NX) but no stack protector
fs_nnx: server.c
	gcc -z execstack -o fs_nnx -g server.c

# All protection mechanisms on
fs: server.c
	gcc -o fs server.c -g
