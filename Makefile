.PHONY: install update

install:
	@pip install --upgrade pip
	@pip install pip-tools
	@pip install -r requirements.txt

update:
	@pip-compile --generate-hashes --resolver=backtracking --output-file=requirements.txt requirements.in
	@pip-sync requirements.txt