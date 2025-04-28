# Special 2FA Generator

This is a Python-based Two-Factor Authentication (2FA) generator tool with enhanced features including device fingerprinting, location verification, and optional OTP speech output.

## Features

- **Device Verification:**  
  The tool generates a unique machine ID by obtaining the MAC address of the device and hashing it using SHA-256. This acts as a device fingerprint to verify the machine running the tool.

- **Location Verification:**  
  The tool uses the IP geolocation API from [ipinfo.io](https://ipinfo.io) to fetch the user's current city and country based on their IP address. This information is displayed to the user and logged for verification purposes.

- **OTP Generation:**  
  Generates Time-based One-Time Passwords (TOTP) using the `pyotp` library, with QR code generation for easy setup in authenticator apps.

- **Emergency Backup Codes:**  
  Generates and manages emergency backup codes stored securely in a JSON file, allowing users to access their account if they lose access to the OTP generator.

- **Speech Output of OTP:**  
  The tool can speak the OTP aloud using the `pyttsx3` text-to-speech library for convenience.

## Command Line Flags

- `--speak`  
  Explicitly enables speaking the OTP aloud. This is the default behavior if no flag is provided.

- `--no-speak`  
  Disables speaking the OTP aloud. Use this flag if you prefer to see the OTP only on the screen without audio output.

These flags are mutually exclusive; you can only use one at a time.

## Installation

1. Clone or download this repository.

2. Install the required Python packages using pip:

   ```bash
   git clone https://github.com/sayantan-saha-cmd/2FA-AUTH.git
   cd 2FA-AUTH
   pip install -r requirements.txt
   ```

   The `requirements.txt` should include:
   ```
   pyotp
   qrcode
   pyttsx3
   requests
   pillow
   ```

3. Run the tool:

   ```bash
   python 2fa-auth.py [--speak | --no-speak]
   ```

   Example:

   - To run with speech output (default):

     ```bash
     python 2fa-auth.py --speak
     ```

   - To run without speech output:

     ```bash
     python 2fa-auth.py --no-speak
     ```

## Usage

- On running, the tool verifies your device and location.
- You will be prompted to enter your passphrase.
- The tool generates and displays your OTP every 30 seconds.
- If speech is enabled, the OTP will be spoken aloud.
- You can use emergency backup codes by typing "yes" when prompted.

## Logging

All important events such as device ID hash, location info, backup code generation, and user actions are logged in `special_2fa_generator.log`.

## License

This project is provided as-is without warranty. Use at your own risk.

---

Created by Sayantan Saha  
LinkedIn: https://www.linkedin.com/in/MasterSayantan/ 
GitHub: https://github.coms/sayantan-saha-cmd/ 
