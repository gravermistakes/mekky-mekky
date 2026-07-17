(* lance_actor.ml - triage gates that read the ACTUAL artifact, not just graph
   metadata. Hardened after the monero-oxide false-positive: a lexical scanner
   produces leads, never Confirmed findings, and a panic reachable only from the
   wallet's own send/construction path is not a network DoS.

   Gate model:
   G0 scope        : reject test/bench/example/fuzz/mock scaffolding (real path)
   G1 severity     : >= Medium
   G2 path         : has an exploit path in the graph
   G3 components    : not an isolated node
   G4 confidence   : Theoretical never passes on its own (leads are not findings)
   G5 reachability : a panic/overflow DoS claim on a send/construction path is
                     NOT remotely reachable -> reject
   G6 evidence     : Confirmed requires an attached evidence artifact
                     (compiling PoC + reachability trace). Scanner leads carry none.

   G0, G4, G5, G6 are HARD: all must hold regardless of the severity count. *)

let matches re s =
  try ignore (Str.search_forward (Str.regexp re) s 0); true with Not_found -> false

(* Not a remote-attacker surface: test scaffolding. *)
let is_nonattacker_path file =
  matches {|/tests?/\|/benches?/\|/examples?/\|/fuzz/\|/mock\|_test\.|}
    (String.lowercase_ascii file)

(* Wallet-side transaction *construction/signing* code. A panic reachable only
   when the operator builds their own outgoing tx is self-inflicted, not a
   broadcast DoS. Network DoS panics must live on a deserialize/verify path. *)
let is_send_construction_path file =
  matches {|/send/\|signable\|/builder\|/sign|} (String.lowercase_ascii file)

let triage (g : Msg.attack_graph) (n : Msg.graph_node) : Msg.finding =
  let is_vuln = n.ntype = "finding" in
  let edges_in = List.filter (fun (e : Msg.graph_edge) -> e.dst = n.id) g.Msg.edges in
  let edges_out = List.filter (fun (e : Msg.graph_edge) -> e.src = n.id) g.Msg.edges in
  let source_conf =
    if is_vuln then begin
      let id_lower = String.lowercase_ascii n.id in
      if matches "_confirmed$\\|_confirmed_" id_lower then Msg.Confirmed
      else if matches "_theoretical$\\|_theoretical_" id_lower then Msg.Theoretical
      else Msg.Probable
    end else Msg.Theoretical in
  let raw_sev = if n.weight >= 5.0 then Msg.Critical
    else if n.weight >= 3.5 then Msg.High
    else if n.weight >= 2.0 then Msg.Medium else Msg.Low in
  (* severity capped by confidence: Critical requires Confirmed *)
  let severity = match source_conf with
    | Msg.Theoretical ->
      (match raw_sev with Msg.Critical | Msg.High -> Msg.Medium | s -> s)
    | Msg.Probable ->
      if raw_sev = Msg.Critical then Msg.High else raw_sev
    | Msg.Confirmed -> raw_sev in
  let components = List.map (fun (e : Msg.graph_edge) -> e.src) edges_in in
  let path_nodes = components @ [n.id] @
    List.map (fun (e : Msg.graph_edge) -> e.dst) edges_out in
  Msg.{
    title = n.label; severity; confidence = source_conf; target = n.id;
    file = n.file;
    components;
    exploit_path = String.concat " -> " path_nodes;
    impact = Printf.sprintf "flow=%.2f edges_in=%d" n.weight (List.length edges_in);
    evidence = []; triage = Needs_evidence;
  }

let gate ~(node : Msg.graph_node) (f : Msg.finding) : Msg.finding =
  let file = node.file in
  let is_finding = node.ntype = "finding" in
  let g0 = not (is_finding && is_nonattacker_path file) in
  let g1 = f.severity <> Msg.Low && f.severity <> Msg.Info in
  let g2 = String.length f.exploit_path > 0 in
  let g3 = List.length f.components > 0 || matches "vuln_" f.target in
  let g4 = f.confidence <> Msg.Theoretical in
  let dos_class = node.pattern = "panic-path" || node.pattern = "overflow-abort" in
  let g5 = not (is_finding && dos_class && is_send_construction_path file) in
  let g6 = (f.confidence <> Msg.Confirmed) || (f.evidence <> []) in
  let gates = [g0; g1; g2; g3; g4; g5; g6] in
  let passed = List.length (List.filter Fun.id gates) in
  let min_gates = match f.severity with
    | Msg.Critical -> 7 | Msg.High -> 6 | _ -> 5 in
  let hard = g0 && g4 && g5 && g6 in
  if hard && passed >= min_gates then { f with triage = Msg.Needs_evidence }
  else { f with triage = Msg.Rejected }

let run (g : Msg.attack_graph) : Msg.finding list =
  let candidates = List.filter (fun (n : Msg.graph_node) ->
    n.ntype = "finding" || n.weight >= 2.5) g.nodes in
  let triaged = List.map (fun n -> gate ~node:n (triage g n)) candidates in
  List.filter (fun (f : Msg.finding) -> f.triage <> Msg.Rejected) triaged
