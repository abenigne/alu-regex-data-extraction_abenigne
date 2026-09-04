import json
import os
import re

# 1. Functions that will help in validation and security


def is_valid_luhn(card_number):
    """
    Checks if a credit card number is real using the Luhn Algorithm (checksum).
    This prevents fake digit sequences from being extracted as valid cards.
    """
    # Remove everything that is not a digit
    digits = [int(char) for char in card_number if char.isdigit()]
    
    # Valid credit cards must have between 13 and 19 digits
    if len(digits) < 13 or len(digits) > 19:
        return False

    checksum = 0
    # Reverse the list of digits to calculate from right to left
    reversed_digits = digits[::-1]

    for index, digit in enumerate(reversed_digits):
        # Double every second digit
        if index % 2 == 1:
            doubled = digit * 2
            # If doubling gives a 2-digit number, subtract 9 (same as adding digits)
            if doubled > 9:
                doubled -= 9
            checksum += doubled
        else:
            checksum += digit

    # A valid card total will be divisible by 10
    return checksum % 10 == 0


def mask_card(card_number):
    """
    Hides all credit card digits except the last 4 with asterisks (*)
    to keep sensitive financial data safe (PCI-DSS compliance).
    """
    # Keep only numbers to count how many digits need masking
    only_digits = re.sub(r'\D', '', card_number)
    masked_digits = ('*' * (len(only_digits) - 4)) + only_digits[-4:]

    # Put the asterisks back into the original text format (keeping spaces/dashes)
    result = []
    digit_counter = 0
    for char in card_number:
        if char.isdigit():
            result.append(masked_digits[digit_counter])
            digit_counter += 1
        else:
            result.append(char)

    return "".join(result)


# ==============================================================================
# 2. CORE EXTRACTION AND VALIDATION LOGIC
# ==============================================================================

def process_text_data(text):
    # Dictionaries and lists to store results and rejected malicious/broken items
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

    # --------------------------------------------------------------------------
    # A. EMAIL EXTRACTION & ALU SUBDOMAIN VALIDATION
    # --------------------------------------------------------------------------
    # Regex Breakdown:
    # \b                   : Word boundary
    # [A-Za-z0-9._%+-]+    : Local part (letters, numbers, dots, pluses, etc.)
    # @                    : Literal @ symbol
    # [A-Za-z0-9.-]+       : Domain name (e.g. gmail, alueducation)
    # \.[A-Za-z]{2,}       : Top-level domain (e.g. .com, .edu)
    # \b                   : Word boundary
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
    found_emails = re.findall(email_pattern, text)

    for email in found_emails:
        # SECURITY CHECK: Reject malformed emails with double dots (e.g. gmail..com or alueducation..com)
        if '..' in email:
            rejected_log.append({"type": "email", "value": email, "reason": "Malformed domain (contains double dots)"})
            continue

        # Add to main email list if not already present
        if email not in results["emails"]["all_valid_emails"]:
            results["emails"]["all_valid_emails"].append(email)

        # ALU Specific Subdomain Classification
        if email.endswith("@alueducation.com"):
            if email not in results["emails"]["alu_official"]:
                results["emails"]["alu_official"].append(email)

        elif email.endswith("@alumni.alueducation.com"):
            if email not in results["emails"]["alu_alumni"]:
                results["emails"]["alu_alumni"].append(email)

        elif email.endswith("@si.alueducation.com"):
            if email not in results["emails"]["alu_si"]:
                results["emails"]["alu_si"].append(email)

    # --------------------------------------------------------------------------
    # B. CREDIT CARD EXTRACTION
    # --------------------------------------------------------------------------
    # Regex Breakdown:
    # \b                   : Start at word boundary
    # (?:\d[ -]*?){13,19}  : Match 13 to 19 digits separated by optional spaces or dashes
    # \b                   : End at word boundary
    card_pattern = r'\b(?:\d[ -]*?){13,19}\b'
    found_cards = re.findall(card_pattern, text)

    for card in found_cards:
        clean_card = card.strip()
        # Validate with Luhn Algorithm before accepting
        if is_valid_luhn(clean_card):
            masked = mask_card(clean_card)
            if masked not in results["credit_cards_masked"]:
                results["credit_cards_masked"].append(masked)
        else:
            rejected_log.append({"type": "credit_card", "value": clean_card, "reason": "Failed Luhn checksum or invalid length"})

    # --------------------------------------------------------------------------
    # C. PHONE NUMBER EXTRACTION
    # --------------------------------------------------------------------------
    # Regex Breakdown:
    # (?:\+?250\s?|0)?     : Optional country code (+250) or leading 0
    # \(?\d{2,3}\)?        : Area code with optional parentheses like (078)
    # [\s.-]?\d{3}         : 3 digits separated by space, dot, or hyphen
    # [\s.-]?\d{3,4}       : Next 3 or 4 digits
    # (?:\s*(?:ext\.|x)\s*\d+)? : Optional extension like "ext. 4"
    phone_pattern = r'(?:\+?250\s?|0)?\(?\d{2,3}\)?[\s.-]?\d{3}[\s.-]?\d{3,4}(?:\s*(?:ext\.|x)\s*\d+)?'
    found_phones = re.findall(phone_pattern, text, re.IGNORECASE)

    for phone in found_phones:
        clean_phone = phone.strip()
        # Only accept if there are at least 9 actual digits
        digits_only = re.sub(r'\D', '', clean_phone)
        if len(digits_only) >= 9:
            if clean_phone not in results["phone_numbers"]:
                results["phone_numbers"].append(clean_phone)

    # --------------------------------------------------------------------------
    # D. URL EXTRACTION & XSS SECURITY FILTERING
    # --------------------------------------------------------------------------
    # Regex Breakdown:
    # \b(?:https?://|www\.) : Must start strictly with http://, https://, or www.
    # [a-zA-Z0-9.-]+        : Domain name
    # \.[a-zA-Z]{2,}        : Domain extension (.com, .org, etc.)
    # (?:/[^\s<>]*)?        : Optional path/parameters excluding spaces and angle brackets
    url_pattern = r'\b(?:https?://|www\.)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s<>]*)?'
    found_urls = re.findall(url_pattern, text)

    for url in found_urls:
        clean_url = url.rstrip('.,')
        
        # SECURITY CHECK: Block XSS script injection attempts
        if "<script" in clean_url.lower() or "javascript:" in clean_url.lower():
            rejected_log.append({"type": "url", "value": clean_url, "reason": "Security Risk: Contains script injection (XSS)"})
        else:
            if clean_url not in results["urls"]:
                results["urls"].append(clean_url)

    # Combine data and security audit into final structure
    return {
        "extracted_data": results,
        "security_audit_log": {
            "rejected_entries": rejected_log
        }
    }


# ==============================================================================
# 3. MAIN SCRIPT EXECUTION
# ==============================================================================

if __name__ == "__main__":
    # Get absolute paths so script can run from any folder
    base_directory = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    input_file_path = os.path.join(base_directory, "input", "raw-text.txt")
    output_file_path = os.path.join(base_directory, "output", "sample-output.json")

    # Read raw text input file
    with open(input_file_path, "r", encoding="utf-8") as file:
        raw_text = file.read()

    # Process and extract data
    output_data = process_text_data(raw_text)

    # Save output as a clean JSON file
    os.makedirs(os.path.dirname(output_file_path), exist_ok=True)
    with open(output_file_path, "w", encoding="utf-8") as file:
        json.dump(output_data, file, indent=4)

    # Print a summary to console
    print("Extraction Complete ")
    print("Saved results to:", output_file_path)
