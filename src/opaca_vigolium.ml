(* opaca_vigolium.ml - native vulnerability scanner. replaces vigolium binary.
   Pattern-based static analysis on Solidity source.
   Zero external deps. Str + Unix only. *)

type severity = Critical | High | Medium | Low | Info
type confidence = Confirmed | Probable | Theoretical

type finding = {
  title : string;
  severity : severity;
  confidence : confidence;
  file : string;
  line : int;
  pattern : string;
  description : string;
}

let sev_to_string = function
  | Critical -> "critical" | High -> "high"
  | Medium -> "medium" | Low -> "low" | Info -> "info"

let conf_to_string = function
  | Confirmed -> "confirmed" | Probable -> "probable"
  | Theoretical -> "theoretical"

(* -- Pattern Detectors -- *)

type detector = {
  id : string;
  title : string;
  sev : severity;
  detect : string -> string -> (int * confidence * string) list;
}

let lines_of content = String.split_on_char '\n' content

let find_pattern_lines re content =
  let lines = lines_of content in
  let acc = ref [] in
  List.iteri (fun i line ->
    (try ignore (Str.search_forward re line 0);
      acc := (i + 1) :: !acc
    with Not_found -> ())
  ) lines;
  List.rev !acc

(* Reentrancy: external call before state update *)
let detect_reentrancy _file content =
  let re_ext_call = Str.regexp {|\.\(call\|transfer\|send\)|} in
  let re_state_write = Str.regexp {|[a-zA-Z_][a-zA-Z0-9_]*[ \t]*[=][ \t]*[^=]|} in
  let re_nonreentrant = Str.regexp "nonReentrant" in
  let lines = lines_of content in
  let findings = ref [] in
  let in_func = ref false in
  let func_start = ref 0 in
  let saw_call = ref false in
  let call_line = ref 0 in
  let has_guard = ref false in
  let brace_depth = ref 0 in
  List.iteri (fun i line ->
    let re_func = Str.regexp {|function[ \t]+[a-zA-Z]|} in
    if (try ignore (Str.search_forward re_func line 0); true with Not_found -> false)
    then begin
      in_func := true; func_start := i; saw_call := false; has_guard := false;
      brace_depth := 0
    end;
    if !in_func then begin
      String.iter (fun c -> match c with
        | '{' -> incr brace_depth | '}' -> decr brace_depth | _ -> ()) line;
      if (try ignore (Str.search_forward re_nonreentrant line 0); true
          with Not_found -> false) then has_guard := true;
      if (try ignore (Str.search_forward re_ext_call line 0); true
          with Not_found -> false) then begin
        saw_call := true; call_line := i + 1
      end;
      if !saw_call && (try ignore (Str.search_forward re_state_write line 0); true
          with Not_found -> false) && not !has_guard then
        findings := (!call_line, Probable,
          "External call before state update without reentrancy guard") :: !findings;
      if !brace_depth <= 0 && i > !func_start then in_func := false
    end
  ) lines;
  !findings

(* Missing access control on state-changing functions *)
let detect_access_control _file content =
  let re_func = Str.regexp {|function[ \t]+\([a-zA-Z_][a-zA-Z0-9_]*\)|} in
  let re_external = Str.regexp {|\(external\|public\)|} in
  let re_view = Str.regexp {|\(view\|pure\)|} in
  let re_guard = Str.regexp {|\(only[A-Za-z]*\|auth\|require.*msg\.sender\|_checkOwner\|nonReentrant\)|} in
  let re_state = Str.regexp {|[a-zA-Z_][a-zA-Z0-9_.]*[ \t]*[=][ \t]*[^=]|} in
  let lines = lines_of content in
  let findings = ref [] in
  let in_header = ref false in
  let header_buf = Buffer.create 128 in
  let func_line = ref 0 in
  List.iteri (fun i line ->
    if (try ignore (Str.search_forward re_func line 0); true with Not_found -> false)
    then begin
      in_header := true;
      Buffer.clear header_buf;
      func_line := i + 1
    end;
    if !in_header then begin
      Buffer.add_string header_buf line;
      Buffer.add_char header_buf ' ';
      if String.contains line '{' || String.contains line ';' then begin
        in_header := false;
        let h = Buffer.contents header_buf in
        let is_ext = try ignore (Str.search_forward re_external h 0); true
          with Not_found -> false in
        let is_view = try ignore (Str.search_forward re_view h 0); true
          with Not_found -> false in
        let has_guard = try ignore (Str.search_forward re_guard h 0); true
          with Not_found -> false in
        let has_state = try ignore (Str.search_forward re_state h 0); true
          with Not_found -> false in
        if is_ext && (not is_view) && (not has_guard) && has_state then
          findings := (!func_line, Probable,
            "External/public state-changing function without access control") :: !findings
      end
    end
  ) lines;
  !findings

(* Unchecked arithmetic in Solidity <0.8 or unchecked blocks *)
let detect_unchecked_math _file content =
  let re_unchecked = Str.regexp "unchecked" in
  let re_arith = Str.regexp {|\(+\|-\|\*\)|} in
  let re_pragma = Str.regexp {|pragma solidity.*0\.\([0-7]\)|} in
  let findings = ref [] in
  let is_old = try ignore (Str.search_forward re_pragma content 0); true
    with Not_found -> false in
  if is_old then
    findings := (1, Probable, "Solidity <0.8 - all arithmetic unchecked by default") :: !findings;
  let lines = lines_of content in
  let in_unchecked = ref false in
  let depth = ref 0 in
  List.iteri (fun i line ->
    if (try ignore (Str.search_forward re_unchecked line 0); true
        with Not_found -> false) then begin
      in_unchecked := true; depth := 0
    end;
    if !in_unchecked then begin
      String.iter (fun c -> match c with
        | '{' -> incr depth | '}' -> decr depth; if !depth <= 0 then in_unchecked := false
        | _ -> ()) line;
      if (try ignore (Str.search_forward re_arith line 0); true with Not_found -> false) then
        findings := (i + 1, Theoretical,
          "Arithmetic in unchecked block - verify overflow safety") :: !findings
    end
  ) lines;
  !findings

(* Dangerous delegatecall *)
let detect_delegatecall _file content =
  let re = Str.regexp "delegatecall" in
  let lines = find_pattern_lines re content in
  List.map (fun l -> (l, Probable, "delegatecall usage - verify target is trusted")) lines

(* tx.origin authentication *)
let detect_tx_origin _file content =
  let re = Str.regexp {|require.*tx\.origin\|tx\.origin.*==|} in
  let lines = find_pattern_lines re content in
  List.map (fun l -> (l, Confirmed, "tx.origin used for auth - phishable")) lines

(* selfdestruct exposure *)
let detect_selfdestruct _file content =
  let re = Str.regexp {|selfdestruct\|suicide|} in
  let lines = find_pattern_lines re content in
  List.map (fun l -> (l, Confirmed, "selfdestruct reachable - verify access control")) lines

(* Uninitialized storage pointer *)
let detect_uninitialized_storage _file content =
  let re = Str.regexp {|[ \t]\(mapping\|uint\|address\|bytes\)[^;]*storage[ \t]+[a-z]|} in
  let lines = find_pattern_lines re content in
  List.map (fun l -> (l, Probable, "Local storage variable - may alias slot 0")) lines

(* Flash loan pattern detection *)
let detect_flash_loan _file content =
  let re = Str.regexp {|flashLoan\|flash_loan\|FlashLoan\|IFlashBorrower|} in
  let lines = find_pattern_lines re content in
  List.map (fun l -> (l, Theoretical, "Flash loan interface - check for price manipulation")) lines

let all_detectors = [
  { id = "reentrancy"; title = "Reentrancy"; sev = High;
    detect = detect_reentrancy };
  { id = "access-control"; title = "Missing Access Control"; sev = High;
    detect = detect_access_control };
  { id = "unchecked-math"; title = "Unchecked Arithmetic"; sev = Medium;
    detect = detect_unchecked_math };
  { id = "delegatecall"; title = "Dangerous Delegatecall"; sev = High;
    detect = fun f c -> detect_delegatecall f c };
  { id = "tx-origin"; title = "tx.origin Auth"; sev = High;
    detect = fun f c -> detect_tx_origin f c };
  { id = "selfdestruct"; title = "Selfdestruct"; sev = Critical;
    detect = fun f c -> detect_selfdestruct f c };
  { id = "uninitialized-storage"; title = "Uninitialized Storage"; sev = Medium;
    detect = fun f c -> detect_uninitialized_storage f c };
  { id = "flash-loan"; title = "Flash Loan Surface"; sev = Info;
    detect = fun f c -> detect_flash_loan f c };
]

let scan_file path =
  let ic = open_in path in
  let content = really_input_string ic (in_channel_length ic) in
  close_in ic;
  let findings = ref [] in
  List.iter (fun det ->
    let hits = det.detect path content in
    List.iter (fun (line, conf, desc) ->
      findings := {
        title = det.title; severity = det.sev; confidence = conf;
        file = path; line; pattern = det.id; description = desc;
      } :: !findings
    ) hits
  ) all_detectors;
  List.rev !findings

let scan_directory dir =
  let findings = ref [] in
  let rec walk d =
    let entries = try Sys.readdir d with _ -> [||] in
    Array.iter (fun e ->
      let path = Filename.concat d e in
      if Sys.is_directory path then
        (if e <> "node_modules" && e <> ".git" && e <> "lib" && e <> "test" then walk path)
      else if Filename.check_suffix e ".sol" then
        (try findings := scan_file path @ !findings with _ -> ())
      else ()
    ) entries
  in
  walk dir;
  !findings

let finding_to_json (f : finding) =
  Printf.sprintf
    {|{"title":%S,"severity":%S,"confidence":%S,"file":%S,"line":%d,"pattern":%S,"description":%S}|}
    f.title (sev_to_string f.severity) (conf_to_string f.confidence)
    f.file f.line f.pattern f.description

let run dir output_path =
  let fs = scan_directory dir in
  let json = "{\"findings\":[" ^
    String.concat ",\n" (List.map finding_to_json fs) ^ "]}" in
  let oc = open_out output_path in
  output_string oc json;
  close_out oc;
  fs
