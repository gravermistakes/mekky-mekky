(* msg.ml — typed message protocol for mechsuit actors *)

type severity = Critical | High | Medium | Low | Info
type confidence = Confirmed | Probable | Theoretical
type triage_status = Accepted | Needs_evidence | Rejected

type endpoint = {
  file : string;
  contract : string;
  name : string;
  visibility : string;
  mutability : string;
  modifiers : string list;
  params : string list;
  state_reads : string list;
  state_writes : string list;
  callees : string list;
  sinks : string list;
}

type vuln_finding = {
  title : string;
  vseverity : severity;
  vconfidence : confidence;
  vfile : string;
  line : int;
  pattern : string;
  description : string;
}

type graph_node = {
  id : string;
  label : string;
  ntype : string;
  mutable weight : float;
  file : string;     (* real source path for finding nodes ("" for endpoints) *)
  pattern : string;  (* detector id for finding nodes ("" for endpoints) *)
}

type graph_edge = {
  src : string;
  dst : string;
  mutable flow : float;
}

type attack_graph = {
  nodes : graph_node list;
  edges : graph_edge list;
}

type finding = {
  title : string;
  severity : severity;
  confidence : confidence;
  target : string;
  file : string;
  components : string list;
  exploit_path : string;
  impact : string;
  evidence : string list;
  mutable triage : triage_status;
}

type witness_entry = {
  phase : string;
  sha256 : string;
  epoch : float;
}

type msg =
  | Target of string
  | Surface of endpoint list
  | Findings of vuln_finding list
  | Graph of attack_graph
  | Ranked of attack_graph
  | Triaged of finding list
  | Witness of witness_entry
  | Keel_halt of string
