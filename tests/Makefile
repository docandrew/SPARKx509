all: tests

tests: *.ads *.adb ../src/*.ads ../src/*.adb tests.gpr
	gprbuild -Ptests -XX509ADA_RUNTIME_CHECKS=enabled -XX509ADA_CONTRACTS=enabled -XX509ADA_BUILD_MODE=debug

clean:
	gprclean -r -Ptests
