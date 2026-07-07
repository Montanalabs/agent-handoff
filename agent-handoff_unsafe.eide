#! VULNERABLE agent-handoff — feeds the untrusted input straight to the tool, no extraction.
#! check -> UNSAFE: tainted data cannot reach a capability.
grant handoff

let raw = fetch<web>
privileged { handoff(raw) }  # tainted -> tool: REJECTED
