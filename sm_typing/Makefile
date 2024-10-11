PYTHONLIBDIR = $(shell python3 -c "import sys; print(sys.path.pop())")
DESTDIR ?= 

.PHONY: install
install:
	install -D -m 644 __init__.py $(DESTDIR)$(PYTHONLIBDIR)/sm_typing.py
	python3 -m compileall $(DESTDIR)$(PYTHONLIBDIR)/sm_typing.py

.PHONY: uninstall
uninstall:
	rm -rf $(DESTDIR)$(PYTHONLIBDIR)/sm_typing.py
	rm -rf $(DESTDIR)$(PYTHONLIBDIR)/__pycache__/sm_typing.*
