(* Executable behavioral contracts for MECHSUIT.
   These tests intentionally describe desired behavior, not current behavior.
   A RED result is an unresolved engineering requirement, not a reason to
   weaken the assertion. Uses the OCaml standard library only. *)

let total = ref 0
let failures = ref 0

let check label assertion =
  incr total;
  try
    if assertion () then Printf.printf "PASS  %s\n%!" label
    else (incr failures; Printf.printf "FAIL  %s\n%!" label)
  with e ->
    incr failures;
    Printf.printf "ERROR %s: %s\n%!" label (Printexc.to_string e)

let contains needle haystack =
  try ignore (Str.search_forward (Str.regexp_string needle) haystack 0); true
  with Not_found -> false

let with_sol source f =
  let path = Filename.temp_file "mechsuit_contract_" ".sol" in
  let oc = open_out path in
  output_string oc source; close_out oc;
  Fun.protect
    ~finally:(fun () -> Sys.remove path)
    (fun () -> f path)

let findings src =
  with_sol src Opaca_vigolium.scan_file

let safe_sol =
  "pragma solidity ^0.8.20;\n" ^
  "contract Calculator {\n" ^
  "  function sum(uint256 a, uint256 b) external pure returns (uint256) {\n" ^
  "    return a + b;\n" ^
  "  }\n" ^
  "}\n"

let bad_reentrancy =
  "pragma solidity ^0.8.20;\n" ^
  "contract Vault {\n" ^
  "  uint256 public balance;\n" ^
  "  function withdraw() external {\n" ^
  "    (bool ok,) = msg.sender.call{value: 1}(\"\");\n" ^
  "    require(ok);\n" ^
  "    balance = 0;\n" ^
  "  }\n" ^
  "}\n"

let () =
  check "Noir: maps contract/function/visibility, not just file count" (fun () ->
    with_sol safe_sol (fun path ->
      let eps = Opaca_noir.parse_solidity_file path in
      List.exists (fun (ep : Opaca_noir.endpoint) ->
        ep.contract = "Calculator" &&
        ep.name = "sum" &&
        ep.visibility = "external" &&
        ep.mutability = "pure") eps));

  check "Noir: ignores decoy function declarations in comments" (fun () ->
    with_sol ("contract Vault {\n" ^
              "  // function steal() external { selfdestruct(payable(msg.sender)); }\n" ^
              "  function keep() external {}\n}\n")
      (fun path ->
        let eps = Opaca_noir.parse_solidity_file path in
        List.exists (fun (e : Opaca_noir.endpoint) -> e.name = "keep") eps &&
        not (List.exists (fun (e : Opaca_noir.endpoint) -> e.name = "steal") eps)));

  check "Vigolium: detects a real call-before-state-update reentrancy lead" (fun () ->
    List.exists (fun (f : Opaca_vigolium.finding) ->
      f.pattern = "reentrancy" && f.line > 0) (findings bad_reentrancy));

  check "Vigolium: safe arithmetic-only contract has zero findings" (fun () ->
    findings safe_sol = []);

  check "Vigolium: comments and strings are not executable vulnerabilities" (fun () ->
    let src =
      "pragma solidity ^0.8.20;\ncontract TextOnly {\n" ^
      "  // selfdestruct and delegatecall and tx.origin == msg.sender\n" ^
      "  string public message = \"selfdestruct delegatecall flashLoan\";\n" ^
      "  function read() external pure returns(uint256) { return 1; }\n}\n" in
    findings src = []);

  check "Vigolium: lexical tx.origin detection must not claim Confirmed" (fun () ->
    let src = "pragma solidity ^0.8.20;\ncontract Unsafe {\n" ^
      "  function check() external view {\n" ^
      "    require(tx.origin == msg.sender);\n  }\n}\n" in
    let fs = findings src in
    List.exists (fun (f : Opaca_vigolium.finding) ->
      f.pattern = "tx-origin") fs &&
    List.for_all (fun (f : Opaca_vigolium.finding) ->
      f.confidence <> Opaca_vigolium.Confirmed) fs);

  check "KEEL: empty explicit allowlist denies targets (fail closed)" (fun () ->
    not (Keel.check_scope ~allowed_targets:[] "/any/target"));

  check "KEEL: only listed targets pass a nonempty allowlist" (fun () ->
    Keel.check_scope ~allowed_targets:["/approved"] "/approved" &&
    not (Keel.check_scope ~allowed_targets:["/approved"] "/other"));

  check "Graph: a file-level finding does not attach to unrelated functions" (fun () ->
    let endpoint name : Msg.endpoint = {
      file = "Vault.sol"; contract = "Vault"; name;
      visibility = "external"; mutability = "nonpayable";
      modifiers = []; params = []; state_reads = []; state_writes = [];
      callees = []; sinks = [];
    } in
    let finding : Msg.vuln_finding = {
      title = "Reentrancy"; vseverity = Msg.High;
      vconfidence = Msg.Probable; vfile = "Vault.sol";
      line = 27; pattern = "reentrancy";
      description = "External call before state update";
    } in
    let g = Graph_actor.build_graph [endpoint "safe"; endpoint "withdraw"] [finding] in
    let incoming = List.filter
      (fun (e : Msg.graph_edge) -> contains "vuln_" e.dst) g.edges in
    (* The graph requires source-line/function ownership to resolve this.
       Connecting both functions is a fabricated exploit-path claim. *)
    List.length incoming = 1 &&
    List.exists (fun (e : Msg.graph_edge) -> e.src = "Vault.withdraw") incoming);

  check "Solver: same graph produces reproducible ranking" (fun () ->
    let n1 : Msg.graph_node = {
      id = "A"; label = "A"; ntype = "endpoint"; weight = 1.;
      file = "A.sol"; pattern = "" } in
    let n2 : Msg.graph_node = {
      id = "B"; label = "B"; ntype = "finding"; weight = 3.;
      file = "A.sol"; pattern = "reentrancy" } in
    let e : Msg.graph_edge = { src = "A"; dst = "B"; flow = 0. } in
    let g : Msg.attack_graph = { nodes = [n1;n2]; edges = [e] } in
    Graph_actor.to_json (Solver_actor.rank g) =
    Graph_actor.to_json (Solver_actor.rank g));

  let node : Msg.graph_node = {
    id = "vuln_1_reentrancy_probable"; label = "Reentrancy";
    ntype = "finding"; weight = 4.; file = "src/Vault.sol";
    pattern = "reentrancy" } in
  let lead : Msg.finding = {
    title = "Reentrancy"; severity = Msg.High; confidence = Msg.Probable;
    target = node.id; file = node.file; components = ["Vault.withdraw"];
    exploit_path = "Vault.withdraw -> vuln_1_reentrancy_probable";
    impact = "potential external call"; evidence = [];
    triage = Msg.Needs_evidence } in

  check "Lance: a lead remains Needs_evidence, never Accepted" (fun () ->
    (Lance_actor.gate ~node lead).triage = Msg.Needs_evidence);

  check "Lance: low-severity leads do not pass minimum-severity gate" (fun () ->
    let low = { lead with severity = Msg.Low } in
    (Lance_actor.gate ~node low).triage = Msg.Rejected);

  check "Lance: Confirmed without evidence is rejected" (fun () ->
    let unproven = { lead with confidence = Msg.Confirmed } in
    (Lance_actor.gate ~node unproven).triage = Msg.Rejected);

  check "Lance: test fixtures cannot become production findings" (fun () ->
    let test_node = { node with file = "tests/Vault.sol" } in
    (Lance_actor.gate ~node:test_node lead).triage = Msg.Rejected);

  check "Report: explicitly labels scanner output as unvalidated" (fun () ->
    let path = Filename.temp_file "mechsuit_report_" ".md" in
    Fun.protect ~finally:(fun () -> Sys.remove path) (fun () ->
      let report = Report_actor.generate [lead] path in
      contains "UNVALIDATED SCANNER LEADS" report &&
      contains "Needs Evidence" report &&
      contains "Total findings: 1" report));

  Printf.printf "\nUnit contracts: %d assertions; %d failed.\n%!" !total !failures;
  if !failures > 0 then exit 1
