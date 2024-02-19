# AKRSign
Tool designed for creating and verifying digital signatures and certificates working with built-in CA. This tool is directly implementing `RSASSA-PKCS1-v1_5` signature schema according to [RFC 8017](https://datatracker.ietf.org/doc/html/rfc8017#section-8.2) for education purposes (university assignment) and it is not intended to be used in any serious security application.
## Installation
```
pip install -r requirements.txt
```
### Running in virtual environment
- Alternatively you can create virtual environment first with:
```
python -m venv .venv
```
- Activate virtual environment with one of the provided activation scripts located in `.venv/Scripts`
- Install requiremnts inside the virtual environment
```
pip install -r requirements.txt
```
## Show help
```
python akrsign.py --help
```
