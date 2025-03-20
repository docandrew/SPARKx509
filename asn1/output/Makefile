all:
	#gnatpp -r *ad?
	gprbuild -gnat2012 -P asn1_x86.gpr mainprogram.adb --subdirs=debug -cargs -g -O0 -gnatwe -gnatwa
	touch builtWithoutCoverage
	
coverage:
	if [ -f builtWithoutCoverage ] ; then make clean ; fi
	#argument -gnatoa was removed because it makes gmat crash.
    #gprbuild -gnat2012 -P asn1_x86.gpr mainprogram.adb --subdirs=debug -cargs -g -O0 -gnatf -gnaty -gnatoa -gnatg -fstack-check -gnatwe -gnatwa -fprofile-arcs -ftest-coverage -largs -fprofile-arcs
	gprbuild -gnat2012 -P asn1_x86.gpr mainprogram.adb --subdirs=debug -cargs -g -O0 -gnatf -gnaty -gnatg -fstack-check -gnatwe -gnatwa -fprofile-arcs -ftest-coverage -largs -fprofile-arcs
	cd obj_x86/debug ; ./mainprogram
	cd obj_x86/debug ; gcov adaasn1rtl pkix1explicit88
	
clean:
	rm -f builtWithoutCoverage ;
	gnat clean -r -P asn1_x86.gpr --subdirs=debug	