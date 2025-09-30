OBJ = code.obj inj_begin.obj inj_code.obj inj_end.obj
CFLAGS = /Ob3 /Os /O1 /c /std:c++20 /EHsc /Tp
LIBS = user32.lib advapi32.lib

all: code.exe

sample: minimal.exe hello.exe messagebox.exe

minimal.exe: sample/minimal.c
	cl.exe sample/minimal.c /link $(LIBS) /OUT:minimal.exe

hello.exe: sample/hello.c
	cl.exe sample/hello.c /link $(LIBS) /OUT:hello.exe

messagebox.exe: sample/messagebox.c
	cl.exe sample/messagebox.c /link $(LIBS) /OUT:messagebox.exe

.cpp.obj:
	cl.exe $(CFLAGS) $<

.asm.obj:
	ml64 /c $<

code.exe: $(OBJ)
	link.exe $(OBJ) $(LIBS) /OUT:code.exe

clean:
	del *.obj
	del minimal.exe hello.exe messagebox.exe

distclean: clean
	del code.exe