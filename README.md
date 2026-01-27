### FM MODEL OF SECURITY POLICIES AND RULES

Preview of new project to use policies and rules of external tools to check vulnerabilities in configurations with UVL.



## How to use it

The usage involves...:

YAML configurations can then be mapped and validated against the model.

## Using the scripts

### Requirements

- [Python 3.9+](https://www.python.org/)
- Git
- Bash or PowerShell for script execution

---

### Download and install

1. Install [Python 3.9+](https://www.python.org/)

2. Clone this repository and enter the project folder:
  ```bash
  git clone https://github.com/CAOSD-group/fm-security-policies.git
  cd fm-security-policies
  ```
3. Create a virtual environment:

  ```bash
  python -m venv envFmSec
  ```

4. Activate the environment:

  - **Linux:**
    ```bash
    source envFmSec/bin/activate
    ```
  - **Windows:**
    ```powershell
    .\envFmSec\Scripts\Activate
    ```

5. Install the dependencies:

  ```bash
  pip install -r requirements.txt
  ```
