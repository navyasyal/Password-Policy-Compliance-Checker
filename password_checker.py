import json
import csv
import re
import os
from collections import Counter


# -------------------------------
# Load Password Policy
# -------------------------------
def load_policy():
    with open("config/policy.json", "r") as file:
        return json.load(file)


# -------------------------------
# Validate Password
# -------------------------------
def validate_password(password, policy):

    issues = []

    if len(password) < policy["min_length"]:
        issues.append("Too Short")

    if policy["require_uppercase"] and not re.search(r"[A-Z]", password):
        issues.append("Missing Uppercase")

    if policy["require_lowercase"] and not re.search(r"[a-z]", password):
        issues.append("Missing Lowercase")

    if policy["require_digit"] and not re.search(r"\d", password):
        issues.append("Missing Digit")

    if policy["require_special"] and not re.search(
        r"[!@#$%^&*(),.?\":{}|<>]", password
    ):
        issues.append("Missing Special Character")

    return issues


# -------------------------------
# Load Passwords CSV
# -------------------------------
def load_passwords():

    passwords = []

    with open("input/passwords.csv", newline="") as csvfile:

        reader = csv.DictReader(csvfile)

        for row in reader:
            passwords.append(row)

    return passwords


# -------------------------------
# Load Common Password List
# -------------------------------
def load_common_passwords():

    with open("input/common_passwords.txt", "r") as file:
        return {line.strip().lower() for line in file}


# -------------------------------
# Detect Password Reuse
# -------------------------------
def find_reused(passwords):

    counts = Counter([user["Password"] for user in passwords])

    reused = []

    for pwd, count in counts.items():
        if count > 1:
            reused.append(pwd)

    return reused


# -------------------------------
# Password Strength Calculator
# -------------------------------
def password_strength(password):

    score = 0

    if len(password) >= 8:
        score += 20

    if len(password) >= 12:
        score += 10

    if re.search(r"[A-Z]", password):
        score += 20

    if re.search(r"[a-z]", password):
        score += 20

    if re.search(r"\d", password):
        score += 15

    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 15

    if score >= 90:
        level = "Strong"
    elif score >= 60:
        level = "Medium"
    else:
        level = "Weak"

    return score, level


# -------------------------------
# Compliance Checker
# -------------------------------
def check_compliance():

    policy = load_policy()

    password_list = load_passwords()

    common_passwords = load_common_passwords()

    reused = find_reused(password_list)

    report = []

    compliant = 0

    non_compliant = 0

    for user in password_list:

        password = user["Password"]

        issues = validate_password(password, policy)

        score, level = password_strength(password)

        if password.lower() in common_passwords:
            issues.append("Common Password")

        if password in reused:
            issues.append("Password Reused")

        if issues:
            status = "FAIL"
            non_compliant += 1
        else:
            status = "PASS"
            compliant += 1

        report.append(
            {
                "Username": user["Username"],
                "Password": password,
                "Status": status,
                "Strength Score": score,
                "Strength Level": level,
                "Issues": ", ".join(issues) if issues else "None",
            }
        )

    return report, compliant, non_compliant


# -------------------------------
# Save CSV Report
# -------------------------------
def save_report(report):

    os.makedirs("output", exist_ok=True)

    with open("output/compliance_report.csv", "w", newline="") as csvfile:

        fields = [
            "Username",
            "Password",
            "Status",
            "Strength Score",
            "Strength Level",
            "Issues",
        ]

        writer = csv.DictWriter(csvfile, fieldnames=fields)

        writer.writeheader()

        writer.writerows(report)


# -------------------------------
# Save Summary
# -------------------------------
def save_summary(total, passed, failed):

    with open("output/summary.txt", "w") as file:

        file.write("Password Policy Compliance Summary\n")
        file.write("=" * 40 + "\n\n")
        file.write(f"Total Passwords : {total}\n")
        file.write(f"Compliant       : {passed}\n")
        file.write(f"Non-Compliant   : {failed}\n")
        file.write(f"Compliance Rate : {(passed / total) * 100:.2f}%\n")


# ===============================================================
# NEW ADDITIONS FOR THE FLASK WEB APPLICATION
# -------------------------------------------------------------
# Nothing above this line has been changed from the original
# command-line project. The functions below are purely additive:
# they reuse the functions above (load_policy, check_compliance,
# save_report, save_summary, etc.) instead of re-implementing any
# password-checking logic. They exist so the Flask app has a way
# to (a) persist edited policy settings and (b) load/upload
# passwords from a location the web app controls, and (c) compute
# a few extra aggregate numbers the dashboard displays.
# ===============================================================


# -------------------------------
# Save Password Policy (new)
# -------------------------------
def save_policy(policy):
    """
    Persists an updated policy dict to config/policy.json.
    Used by the new Settings page. The original project only ever
    *read* the policy (load_policy); this simply adds the ability
    to write it back out in the same format.
    """
    os.makedirs("config", exist_ok=True)

    with open("config/policy.json", "w") as file:
        json.dump(policy, file, indent=4)


# -------------------------------
# Load Passwords From a Custom Path (new)
# -------------------------------
def load_passwords_from(path):
    """
    Same behaviour as load_passwords(), but reads from an arbitrary
    CSV path instead of the hard-coded 'input/passwords.csv'. This
    lets the Flask "Upload CSV" feature analyze a file without
    needing to touch load_passwords() itself.
    """
    passwords = []

    with open(path, newline="") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            passwords.append(row)

    return passwords


# -------------------------------
# Compliance Checker Using a Custom CSV (new)
# -------------------------------
def check_compliance_from(path):
    """
    A thin wrapper around the exact same logic used in
    check_compliance(), except the password list is loaded from
    `path` (the uploaded CSV) rather than the fixed
    'input/passwords.csv'. Every rule (validate_password,
    password_strength, common-password detection, reuse detection)
    is the original, untouched function from above.
    """
    policy = load_policy()

    password_list = load_passwords_from(path)

    common_passwords = load_common_passwords()

    reused = find_reused(password_list)

    report = []
    compliant = 0
    non_compliant = 0

    for user in password_list:
        password = user["Password"]

        issues = validate_password(password, policy)
        score, level = password_strength(password)

        if password.lower() in common_passwords:
            issues.append("Common Password")

        if password in reused:
            issues.append("Password Reused")

        if issues:
            status = "FAIL"
            non_compliant += 1
        else:
            status = "PASS"
            compliant += 1

        report.append(
            {
                "Username": user["Username"],
                "Password": password,
                "Status": status,
                "Strength Score": score,
                "Strength Level": level,
                "Issues": ", ".join(issues) if issues else "None",
            }
        )

    return report, compliant, non_compliant


# -------------------------------
# Extra Aggregate Stats for the Dashboard (new)
# -------------------------------
def get_extra_stats(report):
    """
    Derives the additional numbers the web dashboard needs
    (average strength, weak/common/reused counts, strength
    distribution, and issue-type breakdown) purely from the
    `report` list that check_compliance()/check_compliance_from()
    already produce. No password-checking rule is duplicated here;
    this only tallies data that was already computed above.
    """
    total = len(report)

    if total == 0:
        return {
            "average_strength": 0,
            "weak_count": 0,
            "common_count": 0,
            "reused_count": 0,
            "strength_distribution": {"Strong": 0, "Medium": 0, "Weak": 0},
            "issue_breakdown": {},
        }

    average_strength = round(
        sum(row["Strength Score"] for row in report) / total, 1
    )

    weak_count = sum(1 for row in report if row["Strength Level"] == "Weak")
    common_count = sum(1 for row in report if "Common Password" in row["Issues"])
    reused_count = sum(1 for row in report if "Password Reused" in row["Issues"])

    strength_distribution = {"Strong": 0, "Medium": 0, "Weak": 0}
    for row in report:
        strength_distribution[row["Strength Level"]] += 1

    issue_breakdown = {}
    for row in report:
        if row["Issues"] == "None":
            continue
        for issue in row["Issues"].split(", "):
            issue_breakdown[issue] = issue_breakdown.get(issue, 0) + 1

    return {
        "average_strength": average_strength,
        "weak_count": weak_count,
        "common_count": common_count,
        "reused_count": reused_count,
        "strength_distribution": strength_distribution,
        "issue_breakdown": issue_breakdown,
    }


# -------------------------------
# Main
# -------------------------------
def main():

    report, passed, failed = check_compliance()

    save_report(report)

    save_summary(len(report), passed, failed)

    print("=" * 50)
    print("Password Policy Compliance Checker")
    print("=" * 50)
    print(f"Total Passwords : {len(report)}")
    print(f"Passed          : {passed}")
    print(f"Failed          : {failed}")
    print("Reports saved inside output/")


if __name__ == "__main__":
    main()