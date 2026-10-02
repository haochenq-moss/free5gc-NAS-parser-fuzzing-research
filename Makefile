PYTHON ?= python3

.PHONY: doctor test bootstrap

doctor:
	$(PYTHON) -m free5gc_security_lab doctor

test:
	$(PYTHON) -m unittest discover -s tests -v

bootstrap:
	$(PYTHON) -m free5gc_security_lab bootstrap --ref $${FREE5GC_REF:?Set FREE5GC_REF to a free5GC tag or commit}
