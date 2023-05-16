EXECUTABLE_NAME = algae.run

PATH := venv/bin:$(PATH)

venv:
	python3 -m venv venv
	pip install --upgrade pip
	pip install pyinstaller

build: venv
	pyinstaller -F -c -y -n $(EXECUTABLE_NAME) sources/main.py
.PHONY: build

run:
	python3 sources/main.py
.PHONY: run

clean:
	rm -rf sources/__pycache__
	rm -rf venv
	rm -rf build
	rm -rf dist
	rm -f *.spec
.PHONY: clean
