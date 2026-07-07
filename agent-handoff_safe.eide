#! Multi-agent handoff — untrusted an agent message can only ever become one of a fixed set of decisions over a
#! closed type, never a tool argument. An injected instruction cannot be represented in the
#! closed type, so it is rejected at the trust boundary (and re-clamped at run time by extract).
#! @requires handoff — the multi-agent handoff sink
#! @effect io
#! @taint bridge — extract<Decision> turns the tainted input into a trusted decision
grant handoff

type AgentMsg = Plan | Result | Query
type Decision = Send(AgentMsg) | Stop

let raw = fetch<web>  # UNTRUSTED an agent message — tainted
quarantined { let d = extract<Decision>(raw) }  # only a fixed Decision (payloads too) crosses
privileged { handoff(d) }  # act on the trusted decision only
