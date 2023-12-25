package policy["com.styra.kubernetes.validating"].test.test

import data.policy["com.styra.kubernetes.validating"].rules.rules

test_block_priv_mode {
    in := {
"kind": "AdmissionReview",
"request": {
"kind": {
"kind": "Pod",
"version": "v1"
    },
"object": {
"metadata": {
"name": "myapp"
      },
"spec": {
"containers": [
          {
"image": "nginx:0.1.0",
"name": "nginx-frontend", 
"securityContext": {
"privileged": false
            }
          },
        ]
      }
    }
  }
}
    actual := rules.block_priv_mode with input as in
count(actual) == 0
}