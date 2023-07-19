README.md: README.ipynb
	jupyter nbconvert \
					README.ipynb \
					--ClearOutputPreprocessor.enabled=True \
					--to markdown \
					--output README.md

tampering.md: tampering.ipynb
	jupyter nbconvert \
					tampering.ipynb \
					--ClearOutputPreprocessor.enabled=True \
					--to markdown \
					--output tampering.md
