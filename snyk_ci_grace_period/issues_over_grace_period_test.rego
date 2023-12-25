package main

test_is_past_grace_period_sev1 {
  [year, month, day] := time.date(time.add_date(time.now_ns(),0,0,-15))
  is_past_grace_period_sev1(year, month, day)
}

test_is_past_grace_period_sev1 {
  [year, month, day] := time.date(time.add_date(time.now_ns(),0,0,-14))
  is_past_grace_period_sev1(year, month, day)
}

test_is_past_grace_period_sev1 {
  [year, month, day] := time.date(time.add_date(time.now_ns(),0,0,-13))
  is_past_grace_period_sev1(year, month, day)
}

test_is_past_grace_period_sev2 {
  [year, month, day] := time.date(time.add_date(time.now_ns(),0,0,-91))
  is_past_grace_period_sev2(year, month, day)
}

test_is_past_grace_period_sev2 {
  [year, month, day] := time.date(time.add_date(time.now_ns(),0,0,-90))
  is_past_grace_period_sev2(year, month, day)
}

test_is_past_grace_period_sev2 {
  [year, month, day] := time.date(time.add_date(time.now_ns(),0,0,-89))
  is_past_grace_period_sev2(year, month, day)
}
