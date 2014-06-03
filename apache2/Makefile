# @file: Makefile
# @brief:
# @author: YoungJoo.Kim <http://superlinuxer.com>
# @version: $Revision:
# @date: $Date:

APXS=apxs
EXTRA_CFLAGS=
MOD_NAME=mod_remoteaddr

all: $(MOD_NAME).so

$(MOD_NAME).so: $(MOD_NAME).c
	$(APXS) -c -o $(MOD_NAME).so -Wc,-shared $(MOD_NAME).c

install:
	$(APXS) -i -n $(MOD_NAME) .libs/$(MOD_NAME).so

clean:
	rm -r .libs $(MOD_NAME).{la,lo,o,slo}

