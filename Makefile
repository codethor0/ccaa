PYTHON ?= python3
LATEXMK ?= latexmk
DOT ?= dot
BUILD_DIR ?= build
FIGURE_DOTS := $(wildcard figures/*.dot)
FIGURE_PDFS := $(FIGURE_DOTS:.dot=.pdf)
PAPER := $(BUILD_DIR)/paper.pdf

.PHONY: all figures paper test check clean

all: figures paper check

figures: $(FIGURE_PDFS)

figures/%.pdf: figures/%.dot
	$(DOT) -Tpdf $< -o $@

paper: figures
	mkdir -p $(BUILD_DIR)
	$(LATEXMK) -xelatex -interaction=nonstopmode -halt-on-error -outdir=$(BUILD_DIR) paper.tex

test:
	$(PYTHON) -m unittest discover -s tests -v

check: test
	$(PYTHON) scripts/check_release.py

clean:
	$(LATEXMK) -C -outdir=$(BUILD_DIR) paper.tex || true
	rm -f $(BUILD_DIR)/paper.pdf $(BUILD_DIR)/paper.txt
