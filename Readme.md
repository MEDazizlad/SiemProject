1. **Create a virtual environment**:
    - Open a command line or terminal.
    - Navigate to the root directory of your project.
    - Run the following command to create a new virtual environment named `.venv`:
      ```
      python -m venv .venv
      ```

2. **Activate the virtual environment**:
    - On Windows:
      ```
      .venv\Scripts\activate
      ```
    - On macOS and Linux:
      ```
      source .venv/bin/activate
      ```

3. **Install dependencies from the `requirements.txt` file**:
    - Make sure the virtual environment is activated.
    - Run the following command to install dependencies:
      ```
      pip install -r requirements.txt
      ```
4. **Install WinPcap**:
    - Download NPcap from the following link: https://npcap.com/dist/
    - Or by accessing directly to download link: https://npcap.com/dist/npcap-1.79.exe

5. **Run the application**:
    - Make sure the virtual environment is activated.
    - Run the following command to start the application:
      ```
      python app.py
      ```