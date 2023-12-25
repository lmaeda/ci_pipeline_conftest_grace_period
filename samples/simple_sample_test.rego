package authz

test_post_allowed {
  in := {"path": ["users"], "method": "POST"}
  allow with input as in
}
