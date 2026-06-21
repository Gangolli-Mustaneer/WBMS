# Malware Scanner

A web-based malware scanning application that provides file scanning, URL scanning, and hash scanning capabilities. Built with Flask, YARA rules, and Google Safe Browsing API.

## Features

- File scanning with YARA rules
- URL scanning using Google Safe Browsing API
- Hash scanning against malware database
- Modern, responsive dark UI
- Real-time scanning results
- Drag and drop file upload
- Detailed scan reports

## Prerequisites

- Python 3.7+
- Google Safe Browsing API key
- pip (Python package manager)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd WBMS
```

2. Create a virtual environment and activate it:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install the required packages:
```bash
pip install -r requirements.txt
```

4. Create a `.env` file in the root directory and add your Google Safe Browsing API key:
```
GOOGLE_API_KEY=your_api_key_here
```

## Usage

1. Start the Flask application:
```bash
python app.py
```

2. Open your web browser and navigate to `http://localhost:5000`

3. Use the interface to:
   - Upload and scan files
   - Check URLs for potential threats
   - Verify file hashes against known malware

## Project Structure

```
WBMS/
├── app.py              # Flask application
├── requirements.txt    # Python dependencies
├── rules/             # YARA rules directory
│   └── malware_rules.yar
├── static/            # Static files
│   ├── css/
│   │   └── style.css
│   └── js/
│       └── main.js
├── templates/         # HTML templates
│    └── index.html
├── uploads
├── .env              # API key file
```

## Security Considerations

- The application is designed for educational and testing purposes
- Always scan files in a controlled environment
- Keep your API keys secure and never commit them to version control
- Regularly update YARA rules for better detection

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 
