package policy["com.styra.kubernetes.validating"].test.test

import data.policy["com.styra.kubernetes.validating"].rules.rules

block_priv_mode[decision] {
  #not excludedNamespaces[input.request.namespace]
  data.library.v1.kubernetes.admission.workload.v1.block_privileged_mode[message]

  decision := {
"allowed": false,
"message": message
  }
}

require_audit[decision] {
  data.library.v1.kubernetes.admission.audit.v1.require_auditsink[message]
  decision := {
"allowed": false,
"message": message
  }
}

enforce[decision] {
  block_priv_mode[decision]
}

enforce[decision] {
  require_audit[decision]
}