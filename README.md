This program, which analyzes security in the preloader, is based on a fundamental idea: extracting strings (text) from the binary file. The code reads the file byte-by-byte and then uses a regular expression to capture any readable character string (ASCII), typically ≥ 4 characters long. This is called string extraction.

Afterward, the code converts all the strings to lowercase to facilitate comparison and stores them in a list. This step is important because it prepares the data for analysis.
