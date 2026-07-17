(* report_actor.ml — Immunefi-format report output with witness chain *)

let sev = function
  | Msg.Critical -> "Critical" | Msg.High -> "High"
  | Msg.Medium -> "Medium" | Msg.Low -> "Low" | Msg.Info -> "Info"

let conf = function
  | Msg.Confirmed -> "Confirmed" | Msg.Probable -> "Probable"
  | Msg.Theoretical -> "Theoretical"

let tri = function
  | Msg.Accepted -> "Accepted"
  | Msg.Needs_evidence -> "Needs Evidence"
  | Msg.Rejected -> "Rejected"

let fmt i (f : Msg.finding) =
  Printf.sprintf
    "## Finding %d: %s\n\n\
     | Field | Value |\n|---|---|\n\
     | Severity | %s |\n\
     | Confidence | %s |\n\
     | Triage | %s |\n\
     | Source | `%s` |\n\
     | Node | `%s` |\n\
     | Components | %s |\n\
     | Exploit Path | `%s` |\n\
     | Impact | %s |\n\n"
    (i+1) f.title (sev f.severity) (conf f.confidence) (tri f.triage)
    f.file f.target (String.concat ", " (List.map (Printf.sprintf "`%s`") f.components))
    f.exploit_path f.impact

let generate findings output_path =
  let body = List.mapi fmt findings |> String.concat "\n" in
  let wlog = Witness_actor.dump () in
  let stats = Printf.sprintf
    "- Total findings: %d\n- Critical: %d\n- High: %d\n- Medium: %d\n"
    (List.length findings)
    (List.length (List.filter (fun (f : Msg.finding) -> f.severity = Msg.Critical) findings))
    (List.length (List.filter (fun (f : Msg.finding) -> f.severity = Msg.High) findings))
    (List.length (List.filter (fun (f : Msg.finding) -> f.severity = Msg.Medium) findings))
  in
  let banner =
    "> UNVALIDATED SCANNER LEADS. This is pattern-matched output, not proof.\n\
     > Confidence is capped at `Probable` by construction: a lexical pass cannot\n\
     > demonstrate reachability. Before any of these is written up or submitted,\n\
     > each MUST have (1) a compiling PoC and (2) a traced path from an untrusted\n\
     > entry point (deserialize/verify), not the wallet's own send path.\n\
     > Do NOT relabel anything here as Confirmed without attaching that evidence.\n" in
  let report = Printf.sprintf
    "# MECHSUIT Report\n\n\
     %s\n\
     Generated: %.0f\n\n\
     ## Summary\n\n%s\n\n\
     %s\n\n\
     ---\n\n\
     ## Witness Chain\n\n```\n%s\n```\n"
    banner (Unix.gettimeofday ()) stats body wlog in
  Shell.write_file output_path report;
  report
