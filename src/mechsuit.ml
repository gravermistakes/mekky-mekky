(* mechsuit.ml - the suit. modular toolchain architecture.
   Pipeline: toolchain(surface+findings) -> graph -> solver -> lance -> report
   Toolchains per ecosystem: EVM, Monero, Solana, Move, Bitcoin, Cosmos
   All native OCaml. Zero deps beyond stdlib. *)

let () =
  let target = try Sys.argv.(1) with _ ->
    Printf.eprintf "usage: mechsuit <target_dir> [output_dir] [--toolchain evm|monero|solana]\n"; exit 1 in
  let outdir = try Sys.argv.(2) with _ -> "." in
  (* Optional toolchain override *)
  let forced_tc = try
    let tc_arg = Sys.argv.(3) in
    if tc_arg = "--toolchain" || tc_arg = "-t" then
      Some (try Sys.argv.(4) with _ -> "")
    else None
  with _ -> None in

  if not (Sys.file_exists target && Sys.is_directory target) then begin
    Printf.eprintf "[KEEL] target does not exist: %s\n" target; exit 1
  end;

  (* Detect or force ecosystem *)
  let ecosystem = match forced_tc with
    | Some "evm" | Some "solidity" -> Toolchain.EVM
    | Some "monero" | Some "rust-crypto" -> Toolchain.Monero
    | Some "solana" | Some "anchor" -> Toolchain.Solana
    | Some "move" -> Toolchain.Move
    | Some "bitcoin" | Some "btc" -> Toolchain.Bitcoin
    | Some "cosmos" | Some "go" -> Toolchain.Cosmos
    | _ -> Toolchain.detect_ecosystem target in

  Printf.eprintf "[MECHSUIT] suiting up for %s [%s]\n%!"
    target (Toolchain.ecosystem_to_string ecosystem);

  (* -- WITNESS: boot -- *)
  let _w_boot = Witness_actor.record "boot" target in

  (* -- PHASE 1: TOOLCHAIN-SPECIFIC SURFACE + FINDINGS -- *)
  let noir_out = Filename.concat outdir "mechsuit_noir.json" in
  let vigo_out = Filename.concat outdir "mechsuit_vigolium.json" in

  let (msg_endpoints, msg_findings) = match ecosystem with
    | Toolchain.EVM ->
      Printf.eprintf "[MECHSUIT] phase 1a -- surface mapping (opaca_noir/evm)\n%!";
      let endpoints = Opaca_noir.run target noir_out in
      Printf.eprintf "[NOIR] %d endpoints extracted\n%!" (List.length endpoints);
      Printf.eprintf "[MECHSUIT] phase 1b -- vulnerability scan (opaca_vigolium/evm)\n%!";
      let raw_findings = Opaca_vigolium.run target vigo_out in
      Printf.eprintf "[VIGOLIUM] %d raw findings\n%!" (List.length raw_findings);
      let eps = List.map (fun (ep : Opaca_noir.endpoint) ->
        Msg.{ file = ep.file; contract = ep.contract; name = ep.name;
          visibility = ep.visibility; mutability = ep.mutability;
          modifiers = ep.modifiers; params = ep.params;
          state_reads = ep.state_reads; state_writes = ep.state_writes;
          callees = ep.callees; sinks = ep.sinks }
      ) endpoints in
      let fs = List.map (fun (f : Opaca_vigolium.finding) ->
        let sev = match f.severity with
          | Opaca_vigolium.Critical -> Msg.Critical | High -> Msg.High
          | Medium -> Msg.Medium | Low -> Msg.Low | Info -> Msg.Info in
        let conf = match f.confidence with
          | Opaca_vigolium.Confirmed -> Msg.Confirmed
          | Probable -> Msg.Probable | Theoretical -> Msg.Theoretical in
        Msg.{ title = f.title; vseverity = sev; vconfidence = conf;
          vfile = f.file; line = f.line; pattern = f.pattern;
          description = f.description }
      ) raw_findings in
      (eps, fs)

    | Toolchain.Monero ->
      Printf.eprintf "[MECHSUIT] phase 1a -- surface mapping (toolchain_monero)\n%!";
      let endpoints = Toolchain_monero.run_surface target noir_out in
      Printf.eprintf "[MONERO-NOIR] %d endpoints extracted\n%!" (List.length endpoints);
      Printf.eprintf "[MECHSUIT] phase 1b -- vulnerability scan (toolchain_monero)\n%!";
      let raw_findings = Toolchain_monero.run_findings target vigo_out in
      Printf.eprintf "[MONERO-VIGO] %d raw findings\n%!" (List.length raw_findings);
      (* Convert to Msg types - map Rust endpoint to generic endpoint *)
      let eps = List.map (fun (ep : Toolchain_monero.endpoint) ->
        Msg.{ file = ep.file; contract = ep.module_path; name = ep.name;
          visibility = ep.visibility; mutability = ep.kind;
          modifiers = ep.traits_impl; params = ep.params;
          state_reads = ep.crypto_ops; state_writes = [];
          callees = ep.callees; sinks = ep.sinks }
      ) endpoints in
      let fs = List.map (fun (f : Toolchain_monero.finding) ->
        let sev = match f.severity with
          | Toolchain_monero.Critical -> Msg.Critical | High -> Msg.High
          | Medium -> Msg.Medium | Low -> Msg.Low | Info -> Msg.Info in
        let conf = match f.confidence with
          | Toolchain_monero.Confirmed -> Msg.Confirmed
          | Probable -> Msg.Probable | Theoretical -> Msg.Theoretical in
        Msg.{ title = f.title; vseverity = sev; vconfidence = conf;
          vfile = f.file; line = f.line; pattern = f.pattern;
          description = f.description }
      ) raw_findings in
      (eps, fs)

    | _ ->
      Printf.eprintf "[MECHSUIT] ecosystem %s not yet implemented, falling back to monero\n%!"
        (Toolchain.ecosystem_to_string ecosystem);
      Printf.eprintf "[MECHSUIT] phase 1a -- surface mapping (toolchain_monero)\n%!";
      let endpoints = Toolchain_monero.run_surface target noir_out in
      Printf.eprintf "[MONERO-NOIR] %d endpoints extracted\n%!" (List.length endpoints);
      Printf.eprintf "[MECHSUIT] phase 1b -- vulnerability scan (toolchain_monero)\n%!";
      let raw_findings = Toolchain_monero.run_findings target vigo_out in
      Printf.eprintf "[MONERO-VIGO] %d raw findings\n%!" (List.length raw_findings);
      let eps = List.map (fun (ep : Toolchain_monero.endpoint) ->
        Msg.{ file = ep.file; contract = ep.module_path; name = ep.name;
          visibility = ep.visibility; mutability = ep.kind;
          modifiers = ep.traits_impl; params = ep.params;
          state_reads = ep.crypto_ops; state_writes = [];
          callees = ep.callees; sinks = ep.sinks }
      ) endpoints in
      let fs = List.map (fun (f : Toolchain_monero.finding) ->
        let sev = match f.severity with
          | Toolchain_monero.Critical -> Msg.Critical | High -> Msg.High
          | Medium -> Msg.Medium | Low -> Msg.Low | Info -> Msg.Info in
        let conf = match f.confidence with
          | Toolchain_monero.Confirmed -> Msg.Confirmed
          | Probable -> Msg.Probable | Theoretical -> Msg.Theoretical in
        Msg.{ title = f.title; vseverity = sev; vconfidence = conf;
          vfile = f.file; line = f.line; pattern = f.pattern;
          description = f.description }
      ) raw_findings in
      (eps, fs)
  in

  let _w_noir = Witness_actor.record "surface"
    (string_of_int (List.length msg_endpoints)) in
  let _w_vigo = Witness_actor.record "findings"
    (string_of_int (List.length msg_findings)) in

  (* -- PHASE 2: GRAPH BUILD (ecosystem-agnostic from here) -- *)
  Printf.eprintf "[MECHSUIT] phase 2 -- building attack graph\n%!";
  let graph = Graph_actor.build_graph msg_endpoints msg_findings in
  let graph_json = Graph_actor.to_json graph in
  Shell.write_file (Filename.concat outdir "mechsuit_graph.json") graph_json;
  let _w_graph = Witness_actor.record "graph"
    (Printf.sprintf "%d nodes %d edges"
      (List.length graph.nodes) (List.length graph.edges)) in
  Printf.eprintf "[GRAPH] %d nodes, %d edges\n%!"
    (List.length graph.nodes) (List.length graph.edges);

  (* -- PHASE 3: FLOW RANKING -- *)
  Printf.eprintf "[MECHSUIT] phase 3 -- push propagation ranking\n%!";
  let ranked = Solver_actor.rank graph in
  Shell.write_file (Filename.concat outdir "mechsuit_ranked.json")
    (Graph_actor.to_json ranked);
  let top_w = match ranked.nodes with
    | n :: _ -> n.weight | [] -> 0.0 in
  let _w_solver = Witness_actor.record "solver"
    (Printf.sprintf "top=%.2f" top_w) in
  Printf.eprintf "[SOLVER] top flow: %.2f\n%!" top_w;

  (* -- PHASE 4: 7-GATE TRIAGE -- *)
  Printf.eprintf "[MECHSUIT] phase 4 -- lance 7-gate triage\n%!";
  let triaged = Lance_actor.run ranked in
  let _w_lance = Witness_actor.record "lance"
    (Printf.sprintf "%d passed" (List.length triaged)) in
  Printf.eprintf "[LANCE] %d findings passed gates\n%!" (List.length triaged);

  (* -- KEEL CHECK -- *)
  if Keel.is_halted () then begin
    Printf.eprintf "[KEEL] halted: %s\n" (Keel.reason ()); exit 2
  end;

  (* -- PHASE 5: REPORT -- *)
  Printf.eprintf "[MECHSUIT] phase 5 -- report generation\n%!";
  let report_path = Filename.concat outdir "mechsuit_report.md" in
  let _report = Report_actor.generate triaged report_path in
  let _w_report = Witness_actor.record "report"
    (string_of_int (List.length triaged)) in

  (* -- WITNESS DUMP -- *)
  let witness_path = Filename.concat outdir "mechsuit_witness.log" in
  Shell.write_file witness_path (Witness_actor.dump ());

  Printf.eprintf "[MECHSUIT] complete [%s]\n%!"
    (Toolchain.ecosystem_to_string ecosystem);
  Printf.eprintf "  report:  %s\n" report_path;
  Printf.eprintf "  witness: %s\n" witness_path;
  Printf.eprintf "  findings: %d\n%!" (List.length triaged)
