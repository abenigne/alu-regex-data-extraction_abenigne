# Simple Regex Project

This Python project reads  raw text from a file, finds important pieces of information (like emails, phone numbers, URLs, and credit card numbers), checks if they are safe and valid, and saves the cleaned results into a JSON file.

 # How It Works (Step-by-Step)
Reads Raw Text: The program opens input/raw-text.txt and reads the text line by line.
Finds Data using Regex: We use Regular Expressions (Regex)—which are search patterns—to find four specific types of data:
  Emails: Looks for @ symbols and valid domain extensions.
  Credit Cards: Finds 13 to 19 digit numbers.
  Phone Numbers: Finds phone formats including Rwandan (+250) and local numbers.
  URLs: Finds web links starting with http://, https://, or www..
Validates & Protects (Security):
  ALU Email Check: Categorizes emails ending in @alueducation.com, @alumni.alueducation.com, and @si.alueducation.com.
  Double-Dot Filter: Rejects broken emails with extra dots like gmail..com.
  Luhn Check for Cards: Verifies if credit card numbers are real before accepting them.
  Card Masking: Replaces sensitive credit card digits with asterisks (e.g., 4539 **** **** 6467) to protect personal data.
 Saves Results:
  Valid data is saved under extracted_data.
   Blocked or fake data is logged under security_audit_log.
# How to Run the Program
  Make sure you have Python installed on your computer.
 Open your terminal or command prompt in the main project folder.
 Run the following command:
python src/main.py
Open output/sample-output.json to view the results.
