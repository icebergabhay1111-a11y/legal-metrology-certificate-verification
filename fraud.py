def check_duplicate_serial(cert, existing_certs):
    """
    Rule 1: Duplicate serial
    Checks if the same instrument serial number already has a live certificate under a different owner.
    """
    serial = cert.get("serial_number")
    owner = cert.get("owner_name")

    for existing in existing_certs:
        if existing.get("serial_number") == serial:
            if existing.get("is_live", True) and existing.get("owner_name") != owner:
                cert_id = existing.get("certificate_id", "UNKNOWN")
                return f"Serial {serial} is already certified to a different owner under {cert_id}."
    return None


def check_out_of_jurisdiction(cert):
    """
    Rule 2: Out of jurisdiction
    Checks if an issuing officer or GATC is operating outside assigned jurisdiction or state limits.
    """
    # Officer jurisdiction check
    officer_id = cert.get("officer_id")
    officer_jurisdiction = cert.get("officer_jurisdiction")
    instrument_jurisdiction = cert.get("instrument_jurisdiction")

    if officer_id and officer_jurisdiction and instrument_jurisdiction:
        if officer_jurisdiction != instrument_jurisdiction:
            return (
                f"Officer {officer_id} is assigned to {officer_jurisdiction}; "
                f"this instrument is in {instrument_jurisdiction}."
            )

    # GATC state check
    gatc_id = cert.get("gatc_id")
    gatc_state = cert.get("gatc_approved_state")
    instrument_state = cert.get("instrument_state")

    if gatc_id and gatc_state and instrument_state:
        if gatc_state != instrument_state:
            return (
                f"GATC {gatc_id} is approved for {gatc_state}; "
                f"this instrument is in {instrument_state}."
            )

    return None


def check_improbable_volume(cert, existing_certs, config):
    """
    Rule 3: Improbable volume
    Checks if an officer issues more certificates in a day than allowed by the configuration threshold.
    """
    officer_id = cert.get("officer_id")
    issue_date = cert.get("issue_date")
    limit = config.get("max_daily_certificates_per_officer", 40)

    if not officer_id or not issue_date:
        return None

    # Count certificates issued today by this officer (including the current new certificate)
    daily_count = 1
    for existing in existing_certs:
        if existing.get("officer_id") == officer_id and existing.get("issue_date") == issue_date:
            daily_count += 1

    if daily_count > limit:
        return f"Officer {officer_id} has issued {daily_count} certificates today; the configured limit is {limit}."

    return None


def check_lapsed_and_reregistered(cert, existing_certs):
    """
    Rule 4: Lapsed and re-registered
    Checks if an expired instrument is registered under a new owner without prior re-verification.
    """
    serial = cert.get("serial_number")
    new_owner = cert.get("owner_name")
    is_reverified = cert.get("is_reverified", False)

    if is_reverified:
        return None

    for existing in existing_certs:
        if existing.get("serial_number") == serial:
            if existing.get("is_expired", False) and existing.get("owner_name") != new_owner:
                expiry_date = existing.get("expiry_date", "UNKNOWN")
                return f"Serial {serial} expired on {expiry_date} and has been re-registered without re-verification."

    return None


def run_all_checks(cert, existing_certs, config):
    """
    Runs all fraud detection rules and returns a list of detected issues.
    """
    issues = []

    res1 = check_duplicate_serial(cert, existing_certs)
    if res1:
        issues.append(res1)

    res2 = check_out_of_jurisdiction(cert)
    if res2:
        issues.append(res2)

    res3 = check_improbable_volume(cert, existing_certs, config)
    if res3:
        issues.append(res3)

    res4 = check_lapsed_and_reregistered(cert, existing_certs)
    if res4:
        issues.append(res4)

    return issues