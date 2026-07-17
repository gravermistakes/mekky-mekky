(* opaca_noir.ml - native surface mapper v2. replaces noir binary.
   Parses Solidity source for endpoints, modifiers, state, callees.
   Uses a lightweight token scanner to skip comments/strings before analysis.
   Zero external deps. Str + Unix only. *)

type endpoint = {
  file : string;
  contract : string;
  name : string;
  visibility : string;  (* external|public|internal|private *)
  mutability : string;  (* payable|nonpayable|view|pure *)
  modifiers : string list;
  params : string list;
  returns : string list;
  state_reads : string list;
  state_writes : string list;
  callees : string list;
  sinks : string list;
}

(* -- Fix #1: Lightweight token scanner -- *)
(* Strips comments and string literals, replacing them with spaces.
   This eliminates false brace counts and pattern matches inside
   // comments, /* blocks */, and "string {literals}". *)

let strip_comments_and_strings src =
  let len = String.length src in
  let buf = Buffer.create len in
  let i = ref 0 in
  while !i < len do
    let c = src.[!i] in
    if !i + 1 < len then begin
      let c2 = src.[!i + 1] in
      (* // line comment *)
      if c = '/' && c2 = '/' then begin
        while !i < len && src.[!i] <> '\n' do
          Buffer.add_char buf ' '; incr i
        done
      end
      (* /* block comment */ *)
      else if c = '/' && c2 = '*' then begin
        Buffer.add_char buf ' '; incr i;
        Buffer.add_char buf ' '; incr i;
        while !i + 1 < len && not (src.[!i] = '*' && src.[!i + 1] = '/') do
          if src.[!i] = '\n' then Buffer.add_char buf '\n'
          else Buffer.add_char buf ' ';
          incr i
        done;
        if !i + 1 < len then begin
          Buffer.add_char buf ' '; incr i;
          Buffer.add_char buf ' '; incr i
        end
      end
      (* double-quoted string *)
      else if c = '"' then begin
        Buffer.add_char buf ' '; incr i;
        while !i < len && src.[!i] <> '"' do
          if src.[!i] = '\\' && !i + 1 < len then begin
            Buffer.add_char buf ' '; incr i;
            Buffer.add_char buf ' '; incr i
          end else begin
            Buffer.add_char buf ' '; incr i
          end
        done;
        if !i < len then begin Buffer.add_char buf ' '; incr i end
      end
      (* single-quoted string *)
      else if c = '\'' then begin
        Buffer.add_char buf ' '; incr i;
        while !i < len && src.[!i] <> '\'' do
          if src.[!i] = '\\' && !i + 1 < len then begin
            Buffer.add_char buf ' '; incr i;
            Buffer.add_char buf ' '; incr i
          end else begin
            Buffer.add_char buf ' '; incr i
          end
        done;
        if !i < len then begin Buffer.add_char buf ' '; incr i end
      end
      else begin Buffer.add_char buf c; incr i end
    end else begin Buffer.add_char buf c; incr i end
  done;
  Buffer.contents buf

(* -- Utility -- *)

let lines_of s = String.split_on_char '\n' s

let is_sol_keyword w =
  List.mem w ["if"; "else"; "for"; "while"; "do"; "require"; "assert";
              "revert"; "emit"; "return"; "new"; "delete"; "try"; "catch";
              "unchecked"; "assembly"; "type"; "using"; "import"; "pragma";
              "event"; "error"; "struct"; "enum"; "interface"; "library";
              "contract"; "abstract"; "is"; "mapping"; "memory"; "storage";
              "calldata"; "true"; "false"; "this"; "super"; "msg"; "block";
              "tx"; "abi"; "keccak256"; "sha256"; "ecrecover"; "addmod";
              "mulmod"; "selfdestruct"; "address"; "payable"]

(* -- Fix #3: All endpoint types -- *)
let re_function = Str.regexp {|^\([ \t]*\)\(function\|constructor\|receive\|fallback\)[ \t]*\([A-Za-z_][A-Za-z0-9_]*\)?[ \t]*(|}
let re_func_name = Str.regexp {|function[ \t]+\([A-Za-z_][A-Za-z0-9_]*\)|}

(* -- Fix #2: Multi-contract tracking -- *)
let re_contract_decl = Str.regexp {|\(contract\|abstract contract\|library\|interface\)[ \t]+\([A-Za-z_][A-Za-z0-9_]*\)|}

let re_visibility = Str.regexp {|\(external\|public\|internal\|private\)|}
let re_mutability = Str.regexp {|\(payable\|view\|pure\)|}

(* -- Fix #8: Returns parsing -- *)
let re_returns = Str.regexp {|returns[ \t]*(\([^)]*\))|}

(* -- Fix #5: State var - type-agnostic pattern -- *)
(* Match: <type> [visibility] [mutability] <identifier> ; or = *)
let re_state_line = Str.regexp {|^[ \t]+\([A-Za-z_][A-Za-z0-9_.\[\]]*\)\([ \t]+[a-z]+\)*[ \t]+\([a-zA-Z_][a-zA-Z0-9_]*\)[ \t]*[;=]|}

(* -- Fix #10: Expanded sinks -- *)
let sinks_list = ["selfdestruct"; "delegatecall"; "suicide"; "tx.origin";
                  "assembly"; "staticcall"; "create2"; "create";
                  "prevrandao"; "blockhash"]

let re_sink_pattern = Str.regexp
  {|\(selfdestruct\|delegatecall\|suicide\|tx\.origin\|assembly\|\.staticcall\|\.create2\|\.create\|prevrandao\|blockhash\)|}

(* -- Fix #9: External call patterns -- *)
(* obj.method( | IERC20(x).method( | address(x).method( | super.method( | this.method( *)
let re_ext_call = Str.regexp {|\([A-Za-z_][A-Za-z0-9_]*\)\.\([a-zA-Z_][a-zA-Z0-9_]*\)(|}
let re_cast_call = Str.regexp {|\([A-Za-z_][A-Za-z0-9_]*\)([^)]*)\.\([a-zA-Z_][a-zA-Z0-9_]*\)(|}

(* -- Fix #6: Internal calls with keyword filtering -- *)
let re_internal_call = Str.regexp {|[^.A-Za-z_]\([a-zA-Z_][a-zA-Z0-9_]*\)(|}

(* -- Fix #4: Write detection -- *)
let is_write_of sv body =
  let patterns = [
    Str.regexp (sv ^ "[ \t]*=[^=]");
    Str.regexp (sv ^ "[ \t]*\\+=");
    Str.regexp (sv ^ "[ \t]*-=");
    Str.regexp (sv ^ "[ \t]*\\*=");
    Str.regexp (sv ^ "[ \t]*/=");
    Str.regexp (sv ^ "\\+\\+");
    Str.regexp ("\\+\\+" ^ sv);
    Str.regexp (sv ^ "--");
    Str.regexp ("--" ^ sv);
    Str.regexp ("delete[ \t]+" ^ sv);
    Str.regexp (sv ^ {|\.\(push\|pop\)(|});
    Str.regexp (sv ^ "\\[");  (* array/mapping write: balances[x] *)
  ] in
  List.exists (fun re ->
    try ignore (Str.search_forward re body 0); true
    with Not_found -> false
  ) patterns

(* -- Fix #6: Read detection with word boundaries -- *)
let is_read_of sv body =
  let re = Str.regexp ({|[^A-Za-z0-9_]|} ^ sv ^ {|[^A-Za-z0-9_]|}) in
  try ignore (Str.search_forward re body 0); true
  with Not_found -> false

let find_all_matches re s =
  let acc = ref [] in
  let start = ref 0 in
  (try while true do
    ignore (Str.search_forward re s !start);
    acc := Str.matched_group 1 s :: !acc;
    start := Str.match_end ()
  done with Not_found -> ());
  List.rev !acc

let find_ext_calls s =
  let acc = ref [] in
  let start = ref 0 in
  (try while true do
    ignore (Str.search_forward re_ext_call s !start);
    let obj = Str.matched_group 1 s in
    let meth = Str.matched_group 2 s in
    acc := (obj ^ "." ^ meth) :: !acc;
    start := Str.match_end ()
  done with Not_found -> ());
  (* also try cast calls: IERC20(x).transfer *)
  start := 0;
  (try while true do
    ignore (Str.search_forward re_cast_call s !start);
    let typ = Str.matched_group 1 s in
    let meth = Str.matched_group 2 s in
    acc := (typ ^ "(...)." ^ meth) :: !acc;
    start := Str.match_end ()
  done with Not_found -> ());
  List.rev !acc

let find_internal_calls s =
  let acc = ref [] in
  let start = ref 0 in
  (try while true do
    ignore (Str.search_forward re_internal_call s !start);
    let name = Str.matched_group 1 s in
    (* Fix #5: filter keywords *)
    if not (is_sol_keyword name) then
      acc := name :: !acc;
    start := Str.match_end ()
  done with Not_found -> ());
  List.rev !acc

let find_sinks s =
  find_all_matches re_sink_pattern s

(* -- Fix #7: Modifier extraction -- *)
(* Everything between ) and { in the header that isn't a Solidity keyword
   or visibility/mutability/returns is probably a modifier *)
let extract_modifiers header =
  (* Find content after params closing paren, before opening brace *)
  let after_params = try
    (* find the last ) before { *)
    let brace_pos = try String.index header '{' with Not_found -> String.length header in
    let sub = String.sub header 0 brace_pos in
    (* find last ) *)
    let last_paren = ref 0 in
    String.iteri (fun i c -> if c = ')' then last_paren := i) sub;
    if !last_paren > 0 then
      String.sub sub (!last_paren + 1) (String.length sub - !last_paren - 1)
    else ""
  with _ -> "" in
  (* tokenize and filter *)
  let words = Str.split (Str.regexp {|[ \t\n(,)]+|}) after_params in
  let sol_header_keywords = ["external"; "public"; "internal"; "private";
                             "payable"; "view"; "pure"; "virtual"; "override";
                             "returns"] in
  List.filter (fun w ->
    String.length w > 0 &&
    not (List.mem w sol_header_keywords) &&
    not (is_sol_keyword w) &&
    (* must start with letter/underscore *)
    (let c = w.[0] in (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c = '_')
  ) words

(* -- Fix #8: Extract returns -- *)
let extract_returns header =
  try
    ignore (Str.search_forward re_returns header 0);
    let inner = Str.matched_group 1 header in
    List.filter (fun x -> x <> "")
      (List.map String.trim (String.split_on_char ',' inner))
  with Not_found -> []

let extract_params header =
  (* find first ( ... ) *)
  try
    let start = String.index header '(' in
    let depth = ref 0 in
    let end_pos = ref (start + 1) in
    let found = ref false in
    for i = start to String.length header - 1 do
      if not !found then begin
        (match header.[i] with
         | '(' -> incr depth
         | ')' -> decr depth; if !depth = 0 then begin end_pos := i; found := true end
         | _ -> ())
      end
    done;
    let inner = String.sub header (start + 1) (!end_pos - start - 1) in
    List.filter (fun x -> x <> "")
      (List.map String.trim (String.split_on_char ',' inner))
  with _ -> []

(* -- Main parser -- *)

let parse_solidity_file path =
  let ic = open_in path in
  let raw_content = really_input_string ic (in_channel_length ic) in
  close_in ic;
  (* Fix #1: strip comments and strings for analysis *)
  let content = strip_comments_and_strings raw_content in
  let lines = lines_of content in
  (* Fix #2: Track contract context per-line *)
  let line_contracts = Array.make (List.length lines) "" in
  let current_contract = ref "" in
  let contract_depth = ref 0 in
  let depth = ref 0 in
  List.iteri (fun i line ->
    (* check for contract declaration *)
    (try ignore (Str.search_forward re_contract_decl line 0);
      current_contract := Str.matched_group 2 line;
      contract_depth := !depth
    with Not_found -> ());
    String.iter (fun c -> match c with
      | '{' -> incr depth | '}' -> decr depth | _ -> ()) line;
    if !depth <= !contract_depth && !contract_depth > 0 then
      current_contract := "";
    line_contracts.(i) <- !current_contract
  ) lines;
  (* Fix #5: Extract state variables - type-agnostic *)
  let state_vars = ref [] in
  List.iteri (fun _i line ->
    (try ignore (Str.search_forward re_state_line line 0);
      let vname = Str.matched_group 3 line in
      if not (is_sol_keyword vname) && not (List.mem vname !state_vars) then
        state_vars := vname :: !state_vars
    with Not_found -> ())
  ) lines;
  (* Fix #3: Extract function/constructor/receive/fallback blocks *)
  let func_blocks = ref [] in
  let in_func = ref false in
  let func_depth = ref 0 in
  let func_start_line = ref 0 in
  let current_block = Buffer.create 512 in
  List.iteri (fun i line ->
    if not !in_func then begin
      let is_endpoint =
        (try ignore (Str.search_forward re_function line 0); true
         with Not_found -> false) in
      if is_endpoint then begin
        in_func := true;
        func_start_line := i;
        func_depth := 0;
        Buffer.clear current_block;
        Buffer.add_string current_block line;
        Buffer.add_char current_block '\n';
        String.iter (fun c -> match c with
          | '{' -> incr func_depth | '}' -> decr func_depth | _ -> ()) line;
        if !func_depth <= 0 && String.contains line '{' then begin
          func_blocks := (!func_start_line, Buffer.contents current_block) :: !func_blocks;
          in_func := false
        end
      end
    end else begin
      Buffer.add_string current_block line;
      Buffer.add_char current_block '\n';
      String.iter (fun c -> match c with
        | '{' -> incr func_depth | '}' -> decr func_depth | _ -> ()) line;
      if !func_depth <= 0 then begin
        func_blocks := (!func_start_line, Buffer.contents current_block) :: !func_blocks;
        in_func := false
      end
    end
  ) lines;
  (* Parse each function block *)
  let endpoints = ref [] in
  List.iter (fun (start_line, block) ->
    let header = try
      let idx = String.index block '{' in String.sub block 0 idx
    with Not_found -> block in
    (* Determine name *)
    let name =
      if try ignore (Str.search_forward (Str.regexp "constructor") header 0); true
         with Not_found -> false
      then "constructor"
      else if try ignore (Str.search_forward (Str.regexp "receive") header 0); true
              with Not_found -> false
      then "receive"
      else if try ignore (Str.search_forward (Str.regexp "fallback") header 0); true
              with Not_found -> false
      then "fallback"
      else try
        ignore (Str.search_forward re_func_name header 0);
        Str.matched_group 1 header
      with Not_found -> "" in
    if name <> "" then begin
      let vis = try
        ignore (Str.search_forward re_visibility header 0);
        Str.matched_group 1 header
      with Not_found ->
        if name = "constructor" || name = "receive" || name = "fallback"
        then "external" else "internal" in
      let mut = try
        ignore (Str.search_forward re_mutability header 0);
        Str.matched_group 1 header
      with Not_found ->
        if name = "receive" then "payable" else "nonpayable" in
      (* Fix #7: Extract modifiers *)
      let mods = extract_modifiers header in
      let params = extract_params header in
      (* Fix #8: Extract returns *)
      let returns = extract_returns header in
      (* Fix #9: Find callees *)
      let ext_calls = find_ext_calls block in
      let int_calls = find_internal_calls block in
      let sinks = find_sinks block in
      (* Fix #4 + #6: Reads and writes with word boundaries *)
      let writes = List.filter (fun sv -> is_write_of sv block) !state_vars in
      let reads = List.filter (fun sv -> is_read_of sv block) !state_vars in
      (* Fix #2: Use contract from start line *)
      let contract = if start_line < Array.length line_contracts
        then line_contracts.(start_line) else "" in
      endpoints := {
        file = path; contract;
        name; visibility = vis; mutability = mut;
        modifiers = mods; params; returns;
        state_reads = reads; state_writes = writes;
        callees = ext_calls @ int_calls; sinks;
      } :: !endpoints
    end
  ) !func_blocks;
  List.rev !endpoints

let scan_directory dir =
  let endpoints = ref [] in
  let rec walk d =
    let entries = try Sys.readdir d with _ -> [||] in
    Array.iter (fun e ->
      let path = Filename.concat d e in
      if Sys.is_directory path then
        (if e <> "node_modules" && e <> ".git" && e <> "lib" then walk path)
      else if Filename.check_suffix e ".sol" then
        (try endpoints := parse_solidity_file path @ !endpoints
         with _ -> ())  (* graceful degradation *)
      else ()
    ) entries
  in
  walk dir;
  !endpoints

let endpoint_to_json (ep : endpoint) =
  let list_to_json l = "[" ^ String.concat "," (List.map (Printf.sprintf "%S") l) ^ "]" in
  Printf.sprintf
    {|{"file":%S,"contract":%S,"name":%S,"visibility":%S,"mutability":%S,"modifiers":%s,"params":%s,"returns":%s,"state_reads":%s,"state_writes":%s,"callees":%s,"sinks":%s}|}
    ep.file ep.contract ep.name ep.visibility ep.mutability
    (list_to_json ep.modifiers) (list_to_json ep.params) (list_to_json ep.returns)
    (list_to_json ep.state_reads) (list_to_json ep.state_writes)
    (list_to_json ep.callees) (list_to_json ep.sinks)

let run dir output_path =
  let eps = scan_directory dir in
  let json = "[" ^ String.concat ",\n" (List.map endpoint_to_json eps) ^ "]" in
  let oc = open_out output_path in
  output_string oc json;
  close_out oc;
  eps
