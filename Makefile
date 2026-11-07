.PHONY: serve scan demo test selftest hooks report

serve:
	python3 run.py serve

scan:
	python3 run.py scan .

demo:
	python3 run.py demo

test:
	python3 -m unittest discover -s tests -v

selftest:
	python3 run.py selftest

hooks:
	python3 run.py hooks install

report:
	python3 run.py report --format md