build: locale/responses.pot
	mkdir -p locale/en_US/LC_MESSAGES/
	cp locale/responses.pot locale/en_US/LC_MESSAGES/responses.po
	msgfmt -o locale/en_US/LC_MESSAGES/responses.mo locale/en_US/LC_MESSAGES/responses.po

test:
	nosetests	

run: build
	python main.py
