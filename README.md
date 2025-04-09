# Automatic PDF Organizer & Keyword Extractor 📁🔍

This Python tool automates the process of organizing PDF documents. It scans a directory of PDFs, extracts relevant keywords using the KeyBERT model, saves the keywords to a CSV file, and then categorizes the original PDFs by copying them into subfolders based on predefined rules and the extracted keywords.

It's particularly useful for managing large collections of technical documents, research papers, articles, or any set of PDFs you want to sort by topic.

## ✨ Features

*   **Scans PDF Directory:** Processes all PDF files within a specified source folder.
*   **Text Extraction:** Reads text content from the first few pages of each PDF using PyMuPDF.
*   **Keyword Extraction:** Leverages the powerful [KeyBERT](https://github.com/MaartenGr/KeyBERT) library to identify the most relevant keywords and phrases.
*   **CSV Output:** Saves the extracted keywords along with their relevance scores and corresponding filenames to a structured CSV file (`pdf_keywords.csv` by default).
*   **Console Table:** Displays the extracted keywords in a nicely formatted table in the console upon completion of the extraction phase.
*   **Rule-Based Categorization:** Sorts PDFs into subdirectories based on:
    *   Keywords extracted from the document content.
    *   Patterns found in the PDF filenames.
*   **Customizable Categories:** Easily define your own categories and the keywords/patterns associated with them directly within the script.
*   **Safe Copying:** Copies files into category folders, leaving the original files in the source directory untouched (unless the source directory *is* the target for categorization).

## ⚙️ Installation

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/your-username/your-repository-name.git
    cd your-repository-name
    ```

2.  **Create a Virtual Environment (Recommended):**
    ```bash
    python -m venv venv
    # On Windows
    .\venv\Scripts\activate
    # On macOS/Linux
    source venv/bin/activate
    ```

3.  **Install Dependencies:**
    Make sure you have Python 3.8 or higher installed.
    ```bash
    pip install -r requirements.txt
    ```
    *Note: You'll need to create a `requirements.txt` file with the following content:*

    ```txt
    # requirements.txt
    pymupdf
    keybert
    tabulate
    sentence-transformers
    # Or alternatively, depending on your KeyBERT backend preference:
    # torch
    # tensorflow
    # onnxruntime
    ```
    *Choose the backend (`sentence-transformers`, `torch`, `tensorflow`, `onnxruntime`) that KeyBERT will use. `sentence-transformers` is often the easiest starting point.*

## 🚀 Usage

1.  **Configure the Script:**
    *   Open the `pdf_organizer.py` (or your script's name) file in a text editor.
    *   **Crucially, set the `PDF_SOURCE_DIR` variable** to the absolute or relative path of the directory containing your PDF files.
        ```python
        # --- Configuration ---
        PDF_SOURCE_DIR = r"C:\path\to\your\pdf_directory" # Windows example (use raw string)
        # PDF_SOURCE_DIR = "/path/to/your/pdf_directory"   # Linux/macOS example
        # PDF_SOURCE_DIR = "./my_pdfs"                  # Relative path example
        ```
    *   Optionally, adjust other configuration variables like `OUTPUT_CSV`, `PAGES_TO_SCAN`, `TOP_N_KEYWORDS`, and `DEFAULT_CATEGORY`.

2.  **Customize Categories (Important!):**
    *   Review and modify the `CATEGORY_RULES` dictionary within the script. This is where you define the logic for sorting.
    *   Add/remove categories (the dictionary keys).
    *   For each category, add relevant lowercase `keywords` (as a Python `set`) that should trigger that category.
    *   Optionally, add `filenames` (as a Python `list` of regex patterns) that should trigger that category based on the PDF's filename.
    *   **The order matters!** The script uses the *first* category that matches a rule (either keyword or filename). Place more specific categories higher up in the dictionary.

3.  **Run the Script:**
    Navigate to the script's directory in your terminal (and ensure your virtual environment is activated if you created one) and run:
    ```bash
    python pdf_organizer.py
    ```

4.  **Review Output:**
    *   The script will first process PDFs to extract keywords, printing progress.
    *   It will then display a table of extracted keywords in the console.
    *   A CSV file (e.g., `pdf_keywords.csv`) will be created/overwritten in the script's directory.
    *   Finally, it will categorize and copy the PDFs, creating subfolders within your `PDF_SOURCE_DIR`. Check these folders and the `Uncategorized` folder.

## 🔧 Configuration Variables

You can adjust these variables at the top of the `pdf_organizer.py` script:

*   `PDF_SOURCE_DIR`: (String) Path to the directory containing your PDFs. **(Required to change)**
*   `OUTPUT_CSV`: (String) Name of the CSV file to save keyword results. Default: `"pdf_keywords.csv"`
*   `DEFAULT_CATEGORY`: (String) Name of the folder for PDFs that don't match any category rules. Default: `"Uncategorized"`
*   `PAGES_TO_SCAN`: (Integer) How many pages from the beginning of each PDF to scan for text extraction. Default: `10`
*   `TOP_N_KEYWORDS`: (Integer) How many top keywords KeyBERT should extract per PDF. Default: `5`
*   `CATEGORY_RULES`: (Dictionary) The core logic defining categories, their keywords, and filename patterns. **(Customize this for your needs)**

## 📊 Output

The script produces two main outputs:

1.  **CSV File (`pdf_keywords.csv`):** Contains the following columns:
    *   `Filename`: The name of the original PDF file.
    *   `Keyword`: The keyword extracted by KeyBERT.
    *   `Observability (Score)`: The relevance score (between 0 and 1) assigned by KeyBERT to the keyword for that document.
2.  **Categorized Folders:** Inside the `PDF_SOURCE_DIR`, new subdirectories will be created, named according to the keys in your `CATEGORY_RULES` dictionary (plus the `DEFAULT_CATEGORY`). Copies of the original PDF files will be placed into their corresponding category folders.

## ⚠️ Notes & Troubleshooting

*   **Performance:** The first time you run the script, KeyBERT might take some time to download the underlying sentence transformer model. Processing many large PDFs can also be time-consuming.
*   **Memory Usage:** Keyword extraction models like KeyBERT can be memory-intensive. Ensure you have sufficient RAM.
*   **Dependencies:** Double-check that all libraries listed in `requirements.txt` are installed correctly in your environment.
*   **Encrypted/Corrupted PDFs:** The script uses PyMuPDF. If a PDF is encrypted, password-protected, or heavily corrupted, text extraction might fail, and it might be placed in the `Uncategorized` folder or cause an error message.
*   **Keyword Quality:** The quality of extracted keywords depends heavily on the quality and amount of text extracted from the PDF and the suitability of the KeyBERT model for your specific document types.
*   **Backup:** It is **highly recommended** to back up your original PDF directory before running this script extensively, especially while tuning the `CATEGORY_RULES`.

## 🤝 Contributing

Contributions are welcome! If you have suggestions for improvements, find a bug, or want to add new features, please feel free to open an issue or submit a pull request.

## 📜 License

This project is licensed under the [MIT License](LICENSE). (Or choose another license if you prefer - make sure to add a `LICENSE` file to your repo).
