all: tests

tests: *.ads *.adb ../src/*.ads ../src/*.adb tests.gpr
	gprbuild -Ptests -XSPARKX509_RUNTIME_CHECKS=enabled -XSPARKX509_CONTRACTS=enabled -XSPARKX509_BUILD_MODE=debug

clean:
	gprclean -r -Ptests
