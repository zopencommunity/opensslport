#! /usr/bin/env perl
# Copyright 2009-2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https:#www.openssl.org/source/license.html

#
# ====================================================================
# Written by Andy Polyakov <appro@openssl.org> for the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it. For further
# details see http:#www.openssl.org/~appro/cryptogams/.
# ====================================================================

#
# 2019 Ported to support dual ABI (zLinux/zOS) conventions, converted to use perlasm
# Peter Waltenberg (pwalten@au1.ibm.com), Jonathon Furminger <furming@us.ibm.com>
#

use strict;
use FindBin qw($Bin);
use lib "$Bin/../..";
use perlasm::s390x qw(:MSA :DEFAULT :VX :LD AUTOLOAD LABEL INCLUDE FUNCTION_BEGIN FUNCTION_END BR_EXIT LABEL OBJECT_BEGIN OBJECT_END BYTE LONG ALIGN ASCIZ TEXT GET_EXTERN LOCAL_VARS_BEGIN LOCAL_VARS_END ds);


my $flavour = shift;
my $output;

my ($DSA_OFF,$PARMS_OFF,$z,$SIZE_T,$c1,$c2,$c3);

$DSA_OFF=2048;

if ($flavour =~ /3[12]/) {
   $z=0;	# S/390 ABI
	$SIZE_T=4;
	$PARMS_OFF=2112;
} else {
	$z=1;	# 64 bit
	$SIZE_T=8;
	$PARMS_OFF=2176;
}

my ($p1,$rp,$p2,$ap,$p3,$len,$p4,$rv,$i,$bn3);
my ($zero,$tailLen,$carry,$cnt);
my ($wr6,$wr7,$wr8,$wr9,$wr10,$wr11,$wr13);
if ($flavour =~/linux/) {
	$p1="%r2"; $rv="%r2"; $tailLen="%r2"; $i="%r2"; $cnt="%r1";
	$p2="%r3"; $ap="%r3";
	$p3="%r4"; $len="%r4"; $bn3 = "%r4";
	$p4="%r5";
	
	$zero="%r0";
	$rp="%r1";
	$carry="%r12";
	
	$wr6="%r6";
	$wr7="%r7";		# accumulator?
	$wr8="%r8";
	$wr9="%r9";
	$wr10="%r10";
	$wr11="%r11";
	$wr13="%r13"; 
} else {
	$p1="R1"; $rp="R1";
	$p2="R2"; $ap="R2";
	$p3="R3"; $rv="R3"; $len="R14"; $i="R3";
	$p4="R5"; # Passed in the DSA
	
	$zero="R0";
	$tailLen="R15";
	$carry="R12";
	$cnt="R14";
	
	$wr6="R6";
	$wr7="R7";
	$wr8="R8";
	$wr9="R9";
	$wr10="R10";
	$wr11="R11";
	$wr13="R13"; $bn3 = "R13";
}

while (($output=shift) && ($output!~/\w[\w\-]*\.\w+$/)) {}
open STDOUT,">$output";




PERLASM_BEGIN($flavour,$output);
#my ($rv,$len,$cnt,$cy,$rp,@AP,$i);

TEXT();	
# BN_ULONG bn_mul_add_words(BN_ULONG *r2,BN_ULONG *r3,int r4,BN_ULONG r5);
# BN_ULONG bn_mul_add_words(BN_ULONG *rp,BN_ULONG *ap, int len, BN_ULONG p4);
FUNCTION_BEGIN("bn_mul_add_words",4,"");
	lghi	($zero,0);		# zero = 0, use xor instead
if ($flavour =~ /linux/) {
	la		($rp,"0($p1)");	# put rp aside [to give way to]
} else {	
    if ($z==0) {      # 31 bit z/os returns 64 bit integers in bottom half of R2 and bottom half of R3, save and clear R2 so to not return garbage
        lgr     ("R11","R2");
        lghi    ("R2",0);
    }
	lgr     ($len,$p3);		# Save p3 on z/OS as the reg it is passed in is used for return value
}	   
	lghi	($rv,0);		# return value
	ltgfr	($len,$len);
	BR_EXIT("le");			# if (len<=0) return 0;

	if ($flavour =~ /linux/) {
		stmg	("%r6","%r13","48(%r15)");
	} else {
            if ($z==0) {      # 31 bit z/os returns 64 bit integers in bottom half of R2 and bottom half of R3, restore the previously cleared R2
                lgr     ("R2","R11");
            }
		&{$z? \&lg:\&l} ("R9","$DSA_OFF(R4)");            # Get DSA address
		lg	($p4,"$PARMS_OFF+$SIZE_T*3(R9)"); # Get p4 (which is a 64 bit integer)
	}
	lghi	($tailLen,3);
	lghi	($carry,0);			# carry = 0
	slgr	($rp,$ap);			# rp-=ap
	nr		($tailLen,$len);	# len%4
	sra		($len,2);			# cnt=len/4
	jz		(LABEL("Loop1_madd"));	# carry is incidentally cleared if branch taken
	algr	($zero,$zero);		# clear carry

	lg		($wr7,"0($ap)");	# ap[0]
	lg		($wr9,"8($ap)");	# ap[1]
	mlgr	($wr6,$p4);		# *=w    (must be even-odd pair of regs)
	brct	($len,LABEL("Loop4_madd"));
	j		(LABEL("Loop4_madd_tail"));

LABEL("Loop4_madd:");
	mlgr	($wr8,$p4);
	lg		($wr11,"16($ap)");			# ap[i+2]
	alcgr	($wr7,$carry);				# +=carry
	alcgr	($wr6,$zero);
	alg		($wr7,"0($ap,$rp)");	# +=rp[i]
	stg		($wr7,"0($ap,$rp)");	# rp[i]=

	mlgr	($wr10,$p4);
	lg		($wr13,"24($ap)");
	alcgr	($wr9,$wr6);
	alcgr	($wr8,$zero);
	alg		($wr9,"8($ap,$rp)");
	stg		($wr9,"8($ap,$rp)");

	mlgr	($carry,$p4);
	lg		($wr7,"32($ap)");
	alcgr	($wr11,$wr8);
	alcgr	($wr10,$zero);
	alg		($wr11,"16($ap,$rp)");
	stg		($wr11,"16($ap,$rp)");

	mlgr	($wr6,$p4);
	lg		($wr9,"40($ap)");
	alcgr	($wr13,$wr10);
	alcgr	($carry,$zero);
	alg		($wr13,"24($ap,$rp)");
	stg		($wr13,"24($ap,$rp)");

	la		($ap,"32($ap)");		# i+=4
	brct	($len,LABEL("Loop4_madd"));

LABEL("Loop4_madd_tail:");
	mlgr	($wr8,$p4);
	lg		($wr11,"16($ap)");
	alcgr	($wr7,$carry);				# +=carry
	alcgr	($wr6,$zero);
	alg		($wr7,"0($ap,$rp)");	# +=rp[i]
	stg		($wr7,"0($ap,$rp)");	# rp[i]=

	mlgr	($wr10,$p4);
	lg		($wr13,"24($ap)");
	alcgr	($wr9,$wr6);
	alcgr	($wr8,$zero);
	alg		($wr9,"8($ap,$rp)");
	stg		($wr9,"8($ap,$rp)");

	mlgr	($carry,$p4);
	alcgr	($wr11,$wr8);
	alcgr	($wr10,$zero);
	alg		($wr11,"16($ap,$rp)");
	stg		($wr11,"16($ap,$rp)");

	alcgr	($wr13,$wr10);
	alcgr	($carry,$zero);
	alg		($wr13,"24($ap,$rp)");
	stg		($wr13,"24($ap,$rp)");

	la		($ap,"32($ap)");	# i+=4

	la		($tailLen,"1($tailLen)");		# see if len%4 is zero ...
	brct	($tailLen,LABEL("Loop1_madd"));	# without touching condition code:-)

LABEL("Lend_madd:");
	lgr		($rv,$zero);		# return value
	alcgr	($rv,$carry);		# collect even carry bit
        if ($z==0 && $flavour !~ /linux/) {      # 31 bit z/os returns 64 bit integers in bottom half of R2 and bottom half of R3
            lgr ("R2","R3");
            srag ("R2","R2",32);
        }
	lmg		("%r6","%r13","48(%r15)") if ($flavour =~ /linux/);
	BR_EXIT("");

LABEL("Loop1_madd:");
	lg		($wr7,"0($ap)");	# ap[i]
	mlgr	($wr6,$p4);		# *=w   (Must be an even-odd pair)
	alcgr	($wr7,$carry);		# +=carry
	alcgr	($wr6,$zero);
	alg	($wr7,"0($ap,$rp)");	# +=rp[i]
	stg	($wr7,"0($ap,$rp)");	# rp[i]=

	lgr		($carry,$wr6);
	la		($ap,"8($ap)");		# i++
	brct	($tailLen,LABEL("Loop1_madd"));

	j	(LABEL("Lend_madd"));
FUNCTION_END("bn_mul_add_words",$rv);


# BN_ULONG bn_mul_words(BN_ULONG *r2, BN_ULONG *r3, int r4, BN_ULONG r5);
# BN_ULONG bn_mul_words(BN_ULONG *rp, BN_ULONG *ap, int len, BN_ULONG p4);
FUNCTION_BEGIN("bn_mul_words",4,"");
	lghi	($zero,0);		# zero = 0, use xor instead
if ($flavour =~ /linux/) {
	la	($rp,"0($p1)");		# put rp aside [to give way to]
} else {	
    if ($z==0) {      # 31 bit z/os returns 64 bit integers in bottom half of R2 and bottom half of R3, save and clear R2 so to not return garbage
        lgr     ("R11","R2");
        lghi    ("R2",0);
    }
	lgr     ($len,$p3);		# Save p3 on z/OS as the reg it is passed in is used for return value ($rv)
}	   
	lghi	($rv,0);		# return value
	ltgfr	($len,$len);
	BR_EXIT("le");			# if (len<=0) return 0;

	if ($flavour =~ /linux/) {
		stmg	("%r6","%r13","48(%r15)");
	} else {
            if ($z==0) {      # 31 bit z/os returns 64 bit integers in bottom half of R2 and bottom half of R3, restore the previously cleared R2
                lgr     ("R2","R11");
            }
		&{$z? \&lg:\&l} ("R9","$DSA_OFF(R4)");            # Get DSA address
		lg	($p4,"$PARMS_OFF+$SIZE_T*3(R9)"); # Get p4
	}

	lghi	($wr10,3);
	lghi	($wr8,0);			# carry = 0
	nr		($wr10,$len);		# len%4
	sra		($len,2);			# cnt=len/4
	jz		(LABEL("Loop1_mul"));	# carry is incidentally cleared if branch taken
	algr	($zero,$zero);		# clear carry

LABEL("Loop4_mul:");
	lg		($wr7,"0($i,$ap)");	# ap[i]
	mlgr	($wr6,$p4);			# *=w
	alcgr	($wr7,$wr8);		# +=carry
	stg		($wr7,"0($i,$rp)");	# rp[i]=

	lg		($wr9,"8($i,$ap)");
	mlgr	($wr8,$p4);
	alcgr	($wr9,$wr6);
	stg		($wr9,"8($i,$rp)");

	lg		($wr7,"16($i,$ap)");
	mlgr	($wr6,$p4);
	alcgr	($wr7,$wr8);
	stg		($wr7,"16($i,$rp)");

	lg		($wr9,"24($i,$ap)");
	mlgr	($wr8,$p4);
	alcgr	($wr9,$wr6);
	stg		($wr9,"24($i,$rp)");

	la		($i,"32($i)");	# i+=4
	brct	($len,LABEL("Loop4_mul"));

	la		($wr10,"1($wr10)");			# see if len%4 is zero ...
	brct	($wr10,LABEL("Loop1_mul"));	# without touching condition code:-)

LABEL("Lend_mul:");
	alcgr	($wr8,$zero);	# collect carry bit
	lgr		($rv,$wr8);
        if ($z==0 && $flavour !~ /linux/) {      # 31 bit z/os returns 64 bit integers in bottom half of R2 and bottom half of R3
            lgr ("R2","R3");
            srag ("R2","R2",32);
        }
	lmg		("%r6","%r10","48(%r15)") if ($flavour =~ /linux/);
	BR_EXIT("");

LABEL("Loop1_mul:");
	lg		($wr7,"0($i,$ap)");	# ap[i]
	mlgr	($wr6,$p4);			# *=w
	alcgr	($wr7,$wr8);		# +=carry
	stg		($wr7,"0($i,$rp)");	# rp[i]=

	lgr		($wr8,$wr6);
	la		($i,"8($i)");		# i++
	brct	($wr10,LABEL("Loop1_mul"));

	j		(LABEL("Lend_mul"));
FUNCTION_END("bn_mul_words",$rv);

# void bn_sqr_words(BN_ULONG *r2, BN_ULONG *r2, int r4)
# void bn_sqr_words(BN_ULONG *p1, BN_ULONG *p2, int p3)
FUNCTION_BEGIN("bn_sqr_words",3,"");
	ltgfr	($p3,$p3);
	BR_EXIT("le");

	stmg	("%r6","%r7","48(%r15)") if ($flavour =~ /linux/);
	srag	($cnt,$p3,2);			# cnt=len/4
	jz		(LABEL("Loop1_sqr"));

LABEL("Loop4_sqr:");
	lg		($wr7,"0($p2)");
	mlgr	($wr6,$wr7);
	stg		($wr7,"0($p1)");
	stg		($wr6,"8($p1)");

	lg		($wr7,"8($p2)");
	mlgr	($wr6,$wr7);
	stg		($wr7,"16($p1)");
	stg		($wr6,"24($p1)");

	lg		($wr7,"16($p2)");
	mlgr	($wr6,$wr7);
	stg		($wr7,"32($p1)");
	stg		($wr6,"40($p1)");

	lg		($wr7,"24($p2)");
	mlgr	($wr6,$wr7);
	stg		($wr7,"48($p1)");
	stg		($wr6,"56($p1)");

	la		($p2,"32($p2)");
	la		($p1,"64($p1)");
	brct	($cnt,LABEL("Loop4_sqr"));

	lghi	($cnt,3);
	nr		($p3,$cnt);		# cnt=len%4
	jz		(LABEL("Lend_sqr"));

LABEL("Loop1_sqr:");
	lg		($wr7,"0($p2)");
	mlgr	($wr6,$wr7);
	stg		($wr7,"0($p1)");
	stg		($wr6,"8($p1)");

	la		($p2,"8($p2)");
	la		($p1,"16($p1)");
	brct	($p3,LABEL("Loop1_sqr"));

LABEL("Lend_sqr:");
	lmg	("%r6","%r7","48(%r15)") if ($flavour =~ /linux/);
FUNCTION_END("bn_sqr_words",$rv);


# BN_ULONG bn_div_words(BN_ULONG h,BN_ULONG l,BN_ULONG d);
FUNCTION_BEGIN("bn_div_words",3,"");
if ($flavour =~ /linux/) {
	dlgr	("%r2","%r4");
	lgr		("%r2","%r3");
} else {
    if ($z == 0) {
        l       ("R9","$DSA_OFF(R4)");          # Get DSA address
        lg      ("R6","$PARMS_OFF+8*0(R9)");    # Get h (p1)
        lg      ("R7","$PARMS_OFF+8*1(R9)");    # Get l (p2)
        lg      ("R3","$PARMS_OFF+8*2(R9)");    # Get d (p3)
	dlgr	("R6","R3");
	lgr	("R3","R7");	# return the result
        # 31 bit z/os returns 64 bit integers in bottom half of R2 and bottom half of R3
        lgr  ("R2","R3");
        srag ("R2","R2",32);
} else {
	lgr		("R6","R1");	# dlgr requires first operand to be even-odd pair and z/OS passes parms first parm in r1
	lgr		("R7","R2");
	dlgr	("R6","R3");
	lgr		("R3","R7");	# return the result
}	
}	
FUNCTION_END("bn_div_words",$rv);

# Need adjusting when input parameter # changes
# In this case len comes in in r5
if ($flavour =~/linux/) {
	$p1="%r2"; $rv="%r2"; $tailLen="%r2"; $i="%r2"; $cnt="%r1";
	$p2="%r3"; $ap="%r3";
	$p3="%r4"; $len="%r5"; $bn3 = "%r4";
	$p4="%r5";
	
	$zero="%r0";
	$rp="%r1";
	$carry="%r12";
	
	$wr6="%r6";
	$wr7="%r7";		# accumulator?
	$wr8="%r8";
	$wr9="%r9";
	$wr10="%r10";
	$wr11="%r11";
	$wr13="%r13";
} else {
	$p1="R1"; $rp="R1";
	$p2="R2"; $ap="R2";
	$p3="R3"; $rv="R3"; $len="R14"; $i="R3";
	$p4="R5"; # Passed in the DSA
	
	$zero="R0";
	$tailLen="R15";
	$carry="R12";
	$cnt="R14";
	
	$wr6="R6";
	$wr7="R7";
	$wr8="R8";
	$wr9="R9";
	$wr10="R10";
	$wr11="R11";
	$wr13="R13"; $bn3 = "R13";
}
# BN_ULONG bn_add_words(BN_ULONG *r2, BN_ULONG *r3, BN_ULONG *r4, int r5);
# BN_ULONG bn_add_words(BN_ULONG *p1, BN_ULONG *p2, BN_ULONG *bn3, int p4);
FUNCTION_BEGIN("bn_add_words",4,"");
if ($flavour =~ /linux/) {
	la		($rp,"0($p1)");	# put rp aside
} else {
        if ($z==0) {                     # z/OS returns 64 bit integer return code in the low half of R2 and low half of R3
            lr ("R11","R2");            # save p2 address to be restored after error checking
            lghi ("R2",0);              # clear the R2 part of the 64 bit return code
        }
        lgr    ($bn3,$p3);		# Save p3 on z/OS as the reg it is passed in is used for return value ($rv)
	&{$z? \&lg:\&l} ("R9","$DSA_OFF(R4)");            # Get DSA address
	&{$z? \&lg:\&l}	($len,"$PARMS_OFF+$SIZE_T*3(R9)"); # Get len (p4)
}	
	lghi	($rv,0);		# i=0
	ltgfr	($len,$len);
	BR_EXIT("le"); # if (len<=0) return 0;

        if ($z==0 && $flavour !~ /linux/) {      # Restore R2 which holds p2 on 32 bit z/OS                  
            lr ("R2","R11");            
        }

	stg		($wr6,"48(%r15)") if ($flavour =~ /linux/);
	lghi	($wr6,3);
	nr		($wr6,$len);		# len%4
	sra		($len,2);		# len/4, use sra because it sets condition code
	jz		(LABEL("Loop1_add"));	# carry is incidentally cleared if branch taken
	algr	($i,$i);		# clear carry

LABEL("Loop4_add:");
	lg		($zero,"0($i,$p2)");
	alcg	($zero,"0($i,$bn3)");
	stg		($zero,"0($i,$rp)");
	lg		($zero,"8($i,$p2)");
	alcg	($zero,"8($i,$bn3)");
	stg		($zero,"8($i,$rp)");
	lg		($zero,"16($i,$p2)");
	alcg	($zero,"16($i,$bn3)");
	stg		($zero,"16($i,$rp)");
	lg		($zero,"24($i,$p2)");
	alcg	($zero,"24($i,$bn3)");
	stg		($zero,"24($i,$rp)");

	la		($i,"32($i)");	# i+=4
	brct	($len,LABEL("Loop4_add"));

	la		($wr6,"1($wr6)");	# see if len%4 is zero ...
	brct	($wr6,LABEL("Loop1_add"));	# without touching condition code:-)

LABEL("Lexit_add:");
	lghi	($i,0);
	alcgr	($i,$i);
        if ($z==0 && $flavour !~ /linux/) {      # 31 bit z/os returns 64 bit integers in bottom half of R2 and bottom half of R3
            lgr ("R2","R3");
            srag ("R2","R2",32);
        }
	lg		($wr6,"48(%r15)") if ($flavour =~ /linux/);
	BR_EXIT("");

LABEL("Loop1_add:");
	lg		($zero,"0($i,$p2)");
	alcg	($zero,"0($i,$bn3)");
	stg		($zero,"0($i,$rp)");

	la		($i,"8($i)");	# i++
	brct	($wr6,LABEL("Loop1_add"));

	j	(LABEL("Lexit_add"));
FUNCTION_END("bn_add_words",$rv);

# BN_ULONG bn_sub_words(BN_ULONG *r2, BN_ULONG *r3, BN_ULONG *r4, int r5);
# BN_ULONG bn_sub_words(BN_ULONG *p1, BN_ULONG *p2, BN_ULONG *p3, int p4);
FUNCTION_BEGIN("bn_sub_words",4,"");
if ($flavour =~ /linux/) {
	la		($rp,"0($p1)");		# put rp aside
} else {
    if ($z==0) {      # 31 bit z/os returns 64 bit integers in bottom half of R2 and bottom half of R3, save and clear R2 so to not return garbage
        lgr     ("R11","R2");
        lghi    ("R2",0);
    }
	lgr     ($bn3,$p3);		# Save p3 on z/OS as the reg it is passed in is used for return value ($rv)
	&{$z? \&lg:\&l} ("R9","$DSA_OFF(R4)");            # Get DSA address
	&{$z? \&lg:\&l}	($len,"$PARMS_OFF+$SIZE_T*3(R9)"); # Get len (p4)
}	
	lghi	($rv,0);			# i=0
	ltgfr	($len,$len);
	BR_EXIT("le");		# if (len<=0) return 0;

        if ($z==0 && $flavour !~ /linux/) {      # Restore R2 which holds p2 on 32 bit z/OS                  
            lr ("R2","R11");            
        }
	stg		("%r6","48(%r15)") if ($flavour =~ /linux/);
	lghi	($wr6,3);
	nr		($wr6,$len);		# len%4
	sra		($len,2);			# len/4, use sra because it sets condition code
	jnz		(LABEL("Loop4_sub"));	# borrow is incidentally cleared if branch taken
	slgr	($i,$i);			# clear borrow

LABEL("Loop1_sub:");
	lg		($zero,"0($i,$p2)");
	slbg	($zero,"0($i,$bn3)");
	stg		($zero,"0($i,$rp)");

	la		($i,"8($i)");	# i++
	brct	($wr6,LABEL("Loop1_sub"));
	j		(LABEL("Lexit_sub"));

LABEL("Loop4_sub:");
	lg		($zero,"0($i,$p2)");
	slbg	($zero,"0($i,$bn3)");
	stg		($zero,"0($i,$rp)");
	lg		($zero,"8($i,$p2)");
	slbg	($zero,"8($i,$bn3)");
	stg		($zero,"8($i,$rp)");
	lg		($zero,"16($i,$p2)");
	slbg	($zero,"16($i,$bn3)");
	stg		($zero,"16($i,$rp)");
	lg		($zero,"24($i,$p2)");
	slbg	($zero,"24($i,$bn3)");
	stg		($zero,"24($i,$rp)");

	la		($i,"32($i)");	# i+=4
	brct	($len,LABEL("Loop4_sub"));

	la		($wr6,"1($wr6)");			# see if len%4 is zero ...
	brct	($wr6,LABEL("Loop1_sub"));	# without touching condition code:-)

LABEL("Lexit_sub:");
	lghi	($rv,0);
	slbgr	($rv,$rv);
	lcgr	($rv,$rv);
        if ($z==0 && $flavour !~ /linux/) {      # 31 bit z/os returns 64 bit integers in bottom half of R2 and bottom half of R3
            lgr ("R2","R3");
            srag ("R2","R2",32);
        }
	lg		("%r6","48(%r15)") if ($flavour =~ /linux/);
FUNCTION_END("bn_sub_words",$rv);

my ($c1,$c2,$c3);

if($flavour =~ /linux/) {
	$c1 = "%r1";
	$c2 = "%r5";
	$c3 = "%r8";
	$rp = "%r2";
} else {
	$c1 = "R14";
	$c2 = "R5";
	$c3 = "R8";
}

sub mul_add_c	{
	my $ai = shift;
	my $bi = shift;
	my $c1 = shift;
	my $c2 = shift;
	my $c3 = shift;
	lg	($wr7,"$ai*8($p2)");		
	mlg	($wr6,"$bi*8($p3)");
	algr	($c1,$wr7);
	alcgr	($c2,$wr6);
	alcgr	($c3,$zero);
}

# void bn_mul_comba8(BN_ULONG *r2,BN_ULONG *r3,BN_ULONG *r4);

FUNCTION_BEGIN("bn_mul_comba8",3,"");

	stmg	("%r6","%r8","48(%r15)") if ($flavour =~ /linux/);

	lghi	($c1,0);
	lghi	($c2,0);
	lghi	($c3,0);
	lghi	($zero,0);

	mul_add_c(0,0,$c1,$c2,$c3);
	stg	($c1,"0*8($rp)");
	lghi	($c1,0);

	mul_add_c(0,1,$c2,$c3,$c1);
	mul_add_c(1,0,$c2,$c3,$c1);
	stg	($c2,"1*8($rp)");
	lghi	($c2,0);

	mul_add_c(2,0,$c3,$c1,$c2);
	mul_add_c(1,1,$c3,$c1,$c2);
	mul_add_c(0,2,$c3,$c1,$c2);
	stg	($c3,"2*8($rp)");
	lghi	($c3,0);

	mul_add_c(0,3,$c1,$c2,$c3);
	mul_add_c(1,2,$c1,$c2,$c3);
	mul_add_c(2,1,$c1,$c2,$c3);
	mul_add_c(3,0,$c1,$c2,$c3);
	stg	($c1,"3*8($rp)");
	lghi	($c1,0);

	mul_add_c(4,0,$c2,$c3,$c1);
	mul_add_c(3,1,$c2,$c3,$c1);
	mul_add_c(2,2,$c2,$c3,$c1);
	mul_add_c(1,3,$c2,$c3,$c1);
	mul_add_c(0,4,$c2,$c3,$c1);
	stg	($c2,"4*8($rp)");
	lghi	($c2,0);

	mul_add_c(0,5,$c3,$c1,$c2);
	mul_add_c(1,4,$c3,$c1,$c2);
	mul_add_c(2,3,$c3,$c1,$c2);
	mul_add_c(3,2,$c3,$c1,$c2);
	mul_add_c(4,1,$c3,$c1,$c2);
	mul_add_c(5,0,$c3,$c1,$c2);
	stg	($c3,"5*8($rp)");
	lghi	($c3,0);

	mul_add_c(6,0,$c1,$c2,$c3);
	mul_add_c(5,1,$c1,$c2,$c3);
	mul_add_c(4,2,$c1,$c2,$c3);
	mul_add_c(3,3,$c1,$c2,$c3);
	mul_add_c(2,4,$c1,$c2,$c3);
	mul_add_c(1,5,$c1,$c2,$c3);
	mul_add_c(0,6,$c1,$c2,$c3);
	stg	($c1,"6*8($rp)");
	lghi	($c1,0);

	mul_add_c(0,7,$c2,$c3,$c1);
	mul_add_c(1,6,$c2,$c3,$c1);
	mul_add_c(2,5,$c2,$c3,$c1);
	mul_add_c(3,4,$c2,$c3,$c1);
	mul_add_c(4,3,$c2,$c3,$c1);
	mul_add_c(5,2,$c2,$c3,$c1);
	mul_add_c(6,1,$c2,$c3,$c1);
	mul_add_c(7,0,$c2,$c3,$c1);
	stg	($c2,"7*8($rp)");
	lghi	($c2,0);

	mul_add_c(7,1,$c3,$c1,$c2);
	mul_add_c(6,2,$c3,$c1,$c2);
	mul_add_c(5,3,$c3,$c1,$c2);
	mul_add_c(4,4,$c3,$c1,$c2);
	mul_add_c(3,5,$c3,$c1,$c2);
	mul_add_c(2,6,$c3,$c1,$c2);
	mul_add_c(1,7,$c3,$c1,$c2);
	stg	($c3,"8*8($rp)");
	lghi	($c3,0);

	mul_add_c(2,7,$c1,$c2,$c3);
	mul_add_c(3,6,$c1,$c2,$c3);
	mul_add_c(4,5,$c1,$c2,$c3);
	mul_add_c(5,4,$c1,$c2,$c3);
	mul_add_c(6,3,$c1,$c2,$c3);
	mul_add_c(7,2,$c1,$c2,$c3);
	stg	($c1,"9*8($rp)");
	lghi	($c1,0);

	mul_add_c(7,3,$c2,$c3,$c1);
	mul_add_c(6,4,$c2,$c3,$c1);
	mul_add_c(5,5,$c2,$c3,$c1);
	mul_add_c(4,6,$c2,$c3,$c1);
	mul_add_c(3,7,$c2,$c3,$c1);
	stg	($c2,"10*8($rp)");
	lghi	($c2,0);

	mul_add_c(4,7,$c3,$c1,$c2);
	mul_add_c(5,6,$c3,$c1,$c2);
	mul_add_c(6,5,$c3,$c1,$c2);
	mul_add_c(7,4,$c3,$c1,$c2);
	stg	($c3,"11*8($rp)");
	lghi	($c3,0);

	mul_add_c(7,5,$c1,$c2,$c3);
	mul_add_c(6,6,$c1,$c2,$c3);
	mul_add_c(5,7,$c1,$c2,$c3);
	stg	($c1,"12*8($rp)");
	lghi	($c1,0);


	mul_add_c(6,7,$c2,$c3,$c1);
	mul_add_c(7,6,$c2,$c3,$c1);
	stg	($c2,"13*8($rp)");
	lghi	($c2,0);

	mul_add_c(7,7,$c3,$c1,$c2);
	stg	($c3,"14*8($rp)");
	stg	($c1,"15*8($rp)");

	lmg	("%r6","%r8","48(%r15)")  if ($flavour =~ /linux/);
FUNCTION_END("bn_mul_comba8",$rv);

# void bn_mul_comba4(BN_ULONG *r2,BN_ULONG *r3,BN_ULONG *r4);

FUNCTION_BEGIN("bn_mul_comba4",3,"");
	stmg	("%r6","%r8","48(%r15)") if ($flavour =~ /linux/);

	lghi	($c1,0);
	lghi	($c2,0);
	lghi	($c3,0);
	lghi	($zero,0);

	mul_add_c(0,0,$c1,$c2,$c3);
	stg		($c1,"0*8($p1)");
	lghi	($c1,0);

	mul_add_c(0,1,$c2,$c3,$c1);
	mul_add_c(1,0,$c2,$c3,$c1);
	stg	($c2,"1*8($p1)");
	lghi	($c2,0);

	mul_add_c(2,0,$c3,$c1,$c2);
	mul_add_c(1,1,$c3,$c1,$c2);
	mul_add_c(0,2,$c3,$c1,$c2);
	stg	($c3,"2*8($p1)");
	lghi	($c3,0);

	mul_add_c(0,3,$c1,$c2,$c3);
	mul_add_c(1,2,$c1,$c2,$c3);
	mul_add_c(2,1,$c1,$c2,$c3);
	mul_add_c(3,0,$c1,$c2,$c3);
	stg	($c1,"3*8($p1)");
	lghi	($c1,0);

	mul_add_c(3,1,$c2,$c3,$c1);
	mul_add_c(2,2,$c2,$c3,$c1);
	mul_add_c(1,3,$c2,$c3,$c1);
	stg	($c2,"4*8($p1)");
	lghi	($c2,0);

	mul_add_c(2,3,$c3,$c1,$c2);
	mul_add_c(3,2,$c3,$c1,$c2);
	stg	($c3,"5*8($p1)");
	lghi	($c3,0);

	mul_add_c(3,3,$c1,$c2,$c3);
	stg	($c1,"6*8($p1)");
	stg	($c2,"7*8($p1)");

	stmg	("%r6","%r8","48(%r15)") if ($flavour =~ /linux/);
FUNCTION_END("bn_mul_comba4",$rv);


sub sqr_add_c {
	my $ai = shift;
	my $c1 = shift;
	my $c2 = shift;
	my $c3 = shift;
	lg		($wr7,"$ai*8($p2)");
	mlgr	($wr6,$wr7);	
	algr	($c1,$wr7);
	alcgr	($c2,$wr6);
	alcgr	($c3,$zero);
}

sub sqr_add_c2 {
	my $ai = shift;
	my $aj = shift;
	my $c1 = shift;
	my $c2 = shift;
	my $c3 = shift;	
	lg		($wr7,"$ai*8($p2)");
	mlg		($wr6,"$aj*8($p2)");
	algr	($c1,$wr7);
	alcgr	($c2,$wr6);
	alcgr	($c3,$zero);
	algr	($c1,$wr7);
	alcgr	($c2,$wr6);
	alcgr	($c3,$zero);
}

# void bn_sqr_comba8(BN_ULONG *r2,BN_ULONG *r3);
FUNCTION_BEGIN("bn_sqr_comba8",2,"");

	stmg	("%r6","%r8","48(%r15)") if ($flavour =~ /linux/);

	lghi	($c1,0);
	lghi	($c2,0);
	lghi	($c3,0);
	lghi	($zero,0);

	sqr_add_c(0,$c1,$c2,$c3);
	stg		($c1,"0*8($p1)");
	lghi	($c1,0);

	sqr_add_c2(1,0,$c2,$c3,$c1);
	stg		($c2,"1*8($p1)");
	lghi	($c2,0);

	sqr_add_c(1,$c3,$c1,$c2);
	sqr_add_c2(2,0,$c3,$c1,$c2);
	stg		($c3,"2*8($p1)");
	lghi	($c3,0);

	sqr_add_c2(3,0,$c1,$c2,$c3);
	sqr_add_c2(2,1,$c1,$c2,$c3);
	stg		($c1,"3*8($p1)");
	lghi	($c1,0);

	sqr_add_c(2,$c2,$c3,$c1);
	sqr_add_c2(3,1,$c2,$c3,$c1);
	sqr_add_c2(4,0,$c2,$c3,$c1);
	stg		($c2,"4*8($p1)");
	lghi	($c2,0);

	sqr_add_c2(5,0,$c3,$c1,$c2);
	sqr_add_c2(4,1,$c3,$c1,$c2);
	sqr_add_c2(3,2,$c3,$c1,$c2);
	stg		($c3,"5*8($p1)");
	lghi	($c3,0);

	sqr_add_c(3,$c1,$c2,$c3);
	sqr_add_c2(4,2,$c1,$c2,$c3);
	sqr_add_c2(5,1,$c1,$c2,$c3);
	sqr_add_c2(6,0,$c1,$c2,$c3);
	stg		($c1,"6*8($p1)");
	lghi	($c1,0);

	sqr_add_c2(7,0,$c2,$c3,$c1);
	sqr_add_c2(6,1,$c2,$c3,$c1);
	sqr_add_c2(5,2,$c2,$c3,$c1);
	sqr_add_c2(4,3,$c2,$c3,$c1);
	stg		($c2,"7*8($p1)");
	lghi	($c2,0);

	sqr_add_c(4,$c3,$c1,$c2);
	sqr_add_c2(5,3,$c3,$c1,$c2);
	sqr_add_c2(6,2,$c3,$c1,$c2);
	sqr_add_c2(7,1,$c3,$c1,$c2);
	stg		($c3,"8*8($p1)");
	lghi	($c3,0);

	sqr_add_c2(7,2,$c1,$c2,$c3);
	sqr_add_c2(6,3,$c1,$c2,$c3);
	sqr_add_c2(5,4,$c1,$c2,$c3);
	stg		($c1,"9*8($p1)");
	lghi	($c1,0);

	sqr_add_c(5,$c2,$c3,$c1);
	sqr_add_c2(6,4,$c2,$c3,$c1);
	sqr_add_c2(7,3,$c2,$c3,$c1);
	stg		($c2,"10*8($p1)");
	lghi	($c2,0);

	sqr_add_c2(7,4,$c3,$c1,$c2);
	sqr_add_c2(6,5,$c3,$c1,$c2);
	stg		($c3,"11*8($p1)");
	lghi	($c3,0);

	sqr_add_c(6,$c1,$c2,$c3);
	sqr_add_c2(7,5,$c1,$c2,$c3);
	stg		($c1,"12*8($p1)");
	lghi	($c1,0);

	sqr_add_c2(7,6,$c2,$c3,$c1);
	stg		($c2,"13*8($p1)");
	lghi	($c2,0);

	sqr_add_c(7,$c3,$c1,$c2);
	stg		($c3,"14*8($p1)");
	stg		($c1,"15*8($p1)");

	lmg		("%r6","%r8","48(%r15)") if ($flavour =~ /linux/);
FUNCTION_END("bn_sqr_comba8",$rv);


# void bn_sqr_comba4(BN_ULONG *r2,BN_ULONG *r3);
FUNCTION_BEGIN("bn_sqr_comba4",2,"");

	stmg	("%r6","%r8","48(%r15)") if ($flavour =~ /linux/);

	lghi	($c1,0);
	lghi	($c2,0);
	lghi	($c3,0);
	lghi	($zero,0);

	sqr_add_c(0,$c1,$c2,$c3);
	stg		($c1,"0*8($p1)");
	lghi	($c1,0);

	sqr_add_c2(1,0,$c2,$c3,$c1);
	stg		($c2,"1*8($p1)");
	lghi	($c2,0);

	sqr_add_c(1,$c3,$c1,$c2);
	sqr_add_c2(2,0,$c3,$c1,$c2);
	stg		($c3,"2*8($p1)");
	lghi	($c3,0);

	sqr_add_c2(3,0,$c1,$c2,$c3);
	sqr_add_c2(2,1,$c1,$c2,$c3);
	stg		($c1,"3*8($p1)");
	lghi	($c1,0);

	sqr_add_c(2,$c2,$c3,$c1);
	sqr_add_c2(3,1,$c2,$c3,$c1);
	stg		($c2,"4*8($p1)");
	lghi	($c2,0);

	sqr_add_c2(3,2,$c3,$c1,$c2);
	stg		($c3,"5*8($p1)");
	lghi	($c3,0);

	sqr_add_c(3,$c1,$c2,$c3);
	stg		($c1,"6*8($p1)");
	stg		($c2,"7*8($p1)");

	lmg		("%r6","%r8","48(%r15)") if ($flavour =~ /linux/);
FUNCTION_END("bn_sqr_comba4",$rv);

	PERLASM_END();

