package main

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
# Helper rules to get vulns over grace periods
# Helper rule to get unique medium vulnerabilities
past_gp_unique_medium[vuln.id] {
  vuln = input.vulnerabilities[_]
  not vuln.license
  vuln.isUpgradable   # Check if the vulnerability is upgradable
  vuln.severity == "medium"
  vuln_pubdate_ar = time.date(time.parse_rfc3339_ns(vuln.publicationTime))
  is_past_grace_period_sev2(vuln_pubdate_ar[0], vuln_pubdate_ar[1], vuln_pubdate_ar[2])
}

#Denial rule for unique vulnerabilities with "Medium" severity
deny[msg] {
  count_medium = count(past_gp_unique_medium)
  count_medium > 0
  msg = sprintf("Found %v unique vulnerabilities with Medium severity, that fail security gate.", [count_medium])
}

# Helper rule to get unique High vulnerabilities
past_gp_unique_high[vuln.id] {
  vuln = input.vulnerabilities[_]
  not vuln.license
  vuln.severity == "high"
  vuln_pubdate_ar = time.date(time.parse_rfc3339_ns(vuln.publicationTime))
  is_past_grace_period_sev1(vuln_pubdate_ar[0], vuln_pubdate_ar[1], vuln_pubdate_ar[2])
} 

# Denial rule for unique vulnerabilities with "High" severity
deny[msg] {
  count_high = count(past_gp_unique_high)
  count_high > 0
  msg = sprintf("Found %v unique vulnerabilities with High severity, that fail security gate.", [count_high])
}

# Helper rule to get unique critical vulnerabilities
past_gp_unique_critical[vuln.id] {
  vuln = input.vulnerabilities[_]
  not vuln.license
  vuln.severity == "critical"
  vuln_pubdate_ar = time.date(time.parse_rfc3339_ns(vuln.publicationTime))
  is_past_grace_period_sev1(vuln_pubdate_ar[0], vuln_pubdate_ar[1], vuln_pubdate_ar[2])
}

# Denial rule for unique vulnerabilities with "Critical" severity
deny[msg] {
  count_critical = count(past_gp_unique_critical)
  count_critical > 0
  msg = sprintf("Found %v unique vulnerabilities with Critical severity, that fail security gate.", [count_critical])
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

deny[msg] {
  sast_sev = sast_sev_value
  sast_sev_value = sast_sev_map[_]
  num = count([vuln | vuln = input.runs[_].results[_]; vuln.level == sast_sev_value])
  num > 0 
  msg = sprintf("Found %v code issues with %s severity", [num, sev_map[sast_sev_value]])
}

sast_sev_map = ["warning", "error"]
