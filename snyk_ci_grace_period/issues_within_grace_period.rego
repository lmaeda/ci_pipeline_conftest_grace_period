package main

import future.keywords.in

#Constants for the cutoff date
gp_sev1 := time.date(time.add_date(time.now_ns(),0,0,-14))
gp_sev1_year := gp_sev1[0]
gp_sev1_mon  := gp_sev1[1]
gp_sev1_day  := gp_sev1[2]

gp_sev2 := time.date(time.add_date(time.now_ns(),0,0,-90))
gp_sev2_year := gp_sev2[0]
gp_sev2_mon  := gp_sev2[1]
gp_sev2_day  := gp_sev2[2]


##########################################################
#
##########################################################
#
# Helper rules to get vulns within grace periods
within_gp_unique_medium[msg] {
  vuln := input.vulnerabilities[_]
  not vuln.license
  vuln.isUpgradable   # Check if the vulnerability is upgradable
  vuln.severity == "medium"
  vuln_pubdate_ar = time.date(time.parse_rfc3339_ns(vuln.publicationTime))
  not is_past_grace_period_sev2(vuln_pubdate_ar[0], vuln_pubdate_ar[1], vuln_pubdate_ar[2])
  msg := sprintf(" Issues Details:\nID: %s\n CVE: %s\n CWE: %s\n PackageName: %s\n version: %s\n severity: %s\n publicationTime: %s\n", [vuln.id, vuln.identifiers.CVE[_], vuln.identifiers.CWE[_], vuln.packageName, vuln.version, vuln.severity, vuln.publicationTime])
}

warn[msg] {
  count_warn_medium = count(within_gp_unique_medium)
  count_warn_medium > 0
  msg := sprintf("Found %v unique vulnerabilities with Medium severity within grace period.\n\n", [count_warn_medium])
}

warn[warnMsg] {
  warnMsg := within_gp_unique_medium[_]
}

##########################################################
#
# Helper rule to get unique High vulnerabilities
within_gp_unique_high[msg] {
  vuln := input.vulnerabilities[_]
  not vuln.license
  vuln.severity == "high"
  vuln_pubdate_ar = time.date(time.parse_rfc3339_ns(vuln.publicationTime))
  not is_past_grace_period_sev1(vuln_pubdate_ar[0], vuln_pubdate_ar[1], vuln_pubdate_ar[2])
  msg := sprintf(" Issues Details:\nID: %s\n CVE: %s\n CWE: %s\n PackageName: %s\n version: %s\n severity: %s\n publicationTime: %s\n", [vuln.id, vuln.identifiers.CVE[_], vuln.identifiers.CWE[_], vuln.packageName, vuln.version, vuln.severity, vuln.publicationTime])
} 

# warn rule for unique vulnerabilities with "High" severity
warn[msg] {
  count_warn_high = count(within_gp_unique_high)
  count_warn_high > 0
  msg := sprintf("Found %v unique vulnerabilities with High severity, that fail security gate.", [count_warn_high])
}

warn[warnMsg] {
  warnMsg := within_gp_unique_high[_]
}

##########################################################
#
# Helper rule to get unique critical vulnerabilities
within_gp_unique_critical[msg] {
  vuln := input.vulnerabilities[_]
  not vuln.license
  vuln.severity == "critical"
  vuln_pubdate_ar = time.date(time.parse_rfc3339_ns(vuln.publicationTime))
  not is_past_grace_period_sev1(vuln_pubdate_ar[0], vuln_pubdate_ar[1], vuln_pubdate_ar[2])
  msg := sprintf(" Issues Details:\nID: %s\n CVE: %s\n CWE: %s\n PackageName: %s\n version: %s\n severity: %s\n publicationTime: %s\n", [vuln.id, vuln.identifiers.CVE[_], vuln.identifiers.CWE[_], vuln.packageName, vuln.version, vuln.severity, vuln.publicationTime])
}

# Denial rule for unique vulnerabilities with "Critical" severity
warn[msg] {
  count_warn_critical = count(within_gp_unique_critical)
  count_warn_critical > 0
  msg := sprintf("Found %v unique vulnerabilities with Critical severity, that fail security gate.", [count_warn_critical])
}

warn[warnMsg] {
  warnMsg := within_gp_unique_critical[_]
}

##########################################################
#
# Function to check if the disclosure date is past the sev2 grace period cutoff dates
is_past_grace_period_sev2(pyear, pmonth, pday) {
  gp_sev2_year > pyear
}

is_past_grace_period_sev2(pyear, pmonth, pday) {
  gp_sev2_year == pyear
  gp_sev2_mon > pmonth
}

is_past_grace_period_sev2(pyear, pmonth, pday) {
  gp_sev2_year == pyear
  gp_sev2_mon == pmonth
  gp_sev2_day > pday
}


##########################################################
#
# Function to check if the disclosure date is past the sev1 grace period cutoff date
is_past_grace_period_sev1(pyear, pmonth, pday) {
  gp_sev1_year > pyear
}

is_past_grace_period_sev1(pyear, pmonth, pday) {
  gp_sev1_year == pyear
  gp_sev1_mon > pmonth
}

is_past_grace_period_sev1(pyear, pmonth, pday) {
  gp_sev1_year == pyear
  gp_sev1_mon == pmonth
  gp_sev1_day > pday
}


##########################################################
#
#Denial rule for Code Medium or above serverity issues
sev_map = {
  "warning": "Medium",
  "error": "High"
}

warn[msg] {
  sast_sev = sast_sev_value
  sast_sev_value = sast_sev_map[_]
  num = count([vuln | vuln = input.runs[_].results[_]; vuln.level == sast_sev_value])
  num > 0 
  msg = sprintf("Found %v code issues with %s severity", [num, sev_map[sast_sev_value]])
}

sast_sev_map = ["warning", "error"]
