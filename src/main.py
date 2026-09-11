import json
import os
import re

# This function will help to check if a card number passes the Luhn algorithm( a mathematical checker for id numbers)
def is_valid_luhn(card_number):
    digits = [int(c) for c in card_number if c.isdigit()]
    
    # Checks for the standard card length 
    if len(digits) < 13 or len(digits) > 19:
        return False

    checksum = 0
    reversed_digits = digits[::-1]

    for i, digit in enumerate(reversed_digits):
        if i % 2 == 1:
            doubled = digit * 2
            if doubled > 9:
                doubled -= 9
            checksum += doubled
        else:
            checksum += digit

    return checksum % 10 == 0


# Hides  credit card numbers except last 4 digits
def mask_card(card_number):
    digits = re.sub(r'\D', '', card_number)
    masked = ('*' * (len(digits) - 4)) + digits[-4:]

    result = []
    idx = 0
    for char in card_number:
        if char.isdigit():
              result.append(masked[idx])
              idx += 1
        else:
            result.append(char)

    return "".join(result)


def process_text_data(text):
    results = {
        "emails": {
            "all_valid_emails": [],
            "alu_official": [],
            "alu_alumni": [],
            "alu_si": []
        },
        "credit_cards_masked": [],
        "phone_numbers": [],
        "urls": []
    }
    rejected_log = []

    # 1. This part is to extract and check Emails
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
    found_emails = re.findall(email_pattern, text)

    for email in found_emails:
        # Skips bad email addresses with double dots
        if '..' in email:
            rejected_log.append({
                "type": "email",
                "value": email,
                "reason": "Malformed domain (contains double dots)"
            })
            continue

        if email not in results["emails"]["all_valid_emails"]:
            results["emails"]["all_valid_emails"].append(email)

        # This section is to categorize ALU's population
        if email.endswith("@alueducation.com"):
            if email not in results["emails"]["alu_official"]:
                results["emails"]["alu_official"].append(email)

        elif email.endswith("@alumni.alueducation.com"):
            if email not in results["emails"]["alu_alumni"]:
                results["emails"]["alu_alumni"].append(email)

        elif email.endswith("@si.alueducation.com"):
            if email not in results["emails"]["alu_si"]:
                results["emails"]["alu_si"].append(email)

    # 2. Extract and check Credit Cards
    card_pattern = r'\b(?:\d[ -]*?){13,19}\b'
    found_cards = re.findall(card_pattern, text)

    for card in found_cards:
        clean_card = card.strip()
        # Validate using Luhn
        if is_valid_luhn(clean_card):
            masked = mask_card(clean_card)
            if masked not in results["credit_cards_masked"]:
                results["credit_cards_masked"].append(masked)
        else:
            # Log invalid or fake cards
            rejected_log.append({
                "type": "credit_card",
                "value": clean_card,
                "reason": "Failed Luhn checksum or invalid length"
            })

    # 3. This will extract phone numbers
    phone_pattern = r'(?:\+?250\s?|0)?\(?\d{2,3}\)?[\s.-]?\d{3}[\s.-]?\d{3,4}(?:\s*(?:ext\.|x)\s*\d+)?'
    found_phones = re.findall(phone_pattern, text, re.IGNORECASE)

    for phone in found_phones:
        clean_phone = phone.strip()
        digits_only = re.sub(r'\D', '', clean_phone)
        if len(digits_only) >= 9:
            if clean_phone not in results["phone_numbers"]:
                results["phone_numbers"].append(clean_phone)

    # 4. Extract URLs and filter out scripts
    url_pattern = r'\b(?:https?://|www\.)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s<>]*)?'
    found_urls = re.findall(url_pattern, text)

    for url in found_urls:
        clean_url = url.rstrip('.,')
        
        # Check for XSS script tags
        if "<script" in clean_url.lower() or "javascript:" in clean_url.lower():
            rejected_log.append({
                "type": "url",
                "value": clean_url,
                "reason": "Security Risk: Contains script injection (XSS)"
            })
        else:
            if clean_url not in results["urls"]:
                results["urls"].append(clean_url)

    return {
        "extracted_data": results,
        "security_audit_log": {
            "rejected_entries": rejected_log
        }
    }


if __name__ == "__main__":
    # Get paths relative to project root
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    input_path = os.path.join(base_dir, "input", "raw-text.txt")
    output_path = os.path.join(base_dir, "output", "sample-output.json")

    # Read raw text file
    with open(input_path, "r", encoding="utf-8") as f:
        raw_text = f.read()

    # Process and get extracted dictionary
    data = process_text_data(raw_text)

    # Output
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

    print("Extraction Complete")
    print(f"Saved results to: {output_path}")
