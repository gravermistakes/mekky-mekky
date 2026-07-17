(* toolchain_monero.ml - Monero/Rust crypto ecosystem toolchain.
   Models the real workflow of crypto protocol bug hunters:

   SURFACE MAPPING (what Joern CPG does for C++):
   - Parse Rust source via lightweight token scanner
   - Extract: pub fn, impl blocks, unsafe blocks, trait impls
   - Map: crypto primitives, key material flows, consensus-critical paths

   VULNERABILITY SCANNING (what real auditors check):
   - Constant-time violations (what dudect/timecop/ctgrind detect)
   - Panic paths from public API (what cargo-fuzz/proptest find)
   - Unsafe block soundness (what MIRI catches)
   - Cryptographic invariant violations (what Quarkslab/ToB manually audit)
   - Consensus divergence patterns (what diff-testing against reference finds)
   - Integer overflow under overflow-checks=true (what cargo-careful finds)

   Based on real tools used by Monero auditors:
   - Trail of Bits (RandomX audit): manual + custom static analysis
   - Quarkslab (Bulletproofs audit): formal verification + manual
   - OSTIF/JP Aumasson (CLSAG audit): crypto correctness + fuzzing
   - Veridise (FCMP++ audit): formal methods + implementation review

   Zero external deps. Str + Unix only. *)

(* ═══════════════════════════════════════════════════════════════════
   PART 1: SURFACE MAPPER (replaces opaca_noir for Rust)
   ═══════════════════════════════════════════════════════════════════ *)

type endpoint = {
  file : string;
  module_path : string;  (* crate::module::Type *)
  name : string;
  kind : string;  (* fn|method|trait_impl|unsafe_fn|constructor *)
  visibility : string;  (* pub|pub(crate)|pub(super)|private *)
  is_unsafe : bool;
  is_async : bool;
  generics : string list;
  params : string list;
  returns : string;
  traits_impl : string list;  (* which traits this impl satisfies *)
  unsafe_blocks : int;  (* count of unsafe {} in body *)
  crypto_ops : string list;  (* scalar_mul, hash, sign, verify, etc *)
  state_reads : string list;
  state_writes : string list;
  callees : string list;
  sinks : string list;  (* panic!, unwrap, expect, unreachable!, todo! *)
}

(* Token scanner: strips comments and strings from Rust source *)
let strip_rust_comments_and_strings src =
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
          Buffer.add_char buf ' '; incr i done
      end
      (* /* block comment */ - Rust allows nesting *)
      else if c = '/' && c2 = '*' then begin
        let depth = ref 1 in
        Buffer.add_char buf ' '; incr i;
        Buffer.add_char buf ' '; incr i;
        while !i < len && !depth > 0 do
          if !i + 1 < len && src.[!i] = '/' && src.[!i+1] = '*' then
            (incr depth; Buffer.add_char buf ' '; incr i;
             Buffer.add_char buf ' '; incr i)
          else if !i + 1 < len && src.[!i] = '*' && src.[!i+1] = '/' then
            (decr depth; Buffer.add_char buf ' '; incr i;
             Buffer.add_char buf ' '; incr i)
          else begin
            (if src.[!i] = '\n' then Buffer.add_char buf '\n'
             else Buffer.add_char buf ' ');
            incr i
          end
        done
      end
      (* raw string r#"..."# *)
      else if c = 'r' && c2 = '#' then begin
        Buffer.add_char buf ' '; incr i;
        (* count hashes *)
        let hashes = ref 0 in
        while !i < len && src.[!i] = '#' do
          incr hashes; Buffer.add_char buf ' '; incr i done;
        (* skip opening quote *)
        if !i < len && src.[!i] = '"' then
          (Buffer.add_char buf ' '; incr i);
        (* find closing quote+hashes *)
        let closed = ref false in
        while !i < len && not !closed do
          if src.[!i] = '"' then begin
            let j = ref (!i + 1) in
            let count = ref 0 in
            while !j < len && src.[!j] = '#' && !count < !hashes do
              incr count; incr j done;
            if !count = !hashes then
              (closed := true; i := !j)
            else (Buffer.add_char buf ' '; incr i)
          end else begin
            if src.[!i] = '\n' then Buffer.add_char buf '\n'
            else Buffer.add_char buf ' ';
            incr i
          end
        done
      end
      (* double-quoted string *)
      else if c = '"' then begin
        Buffer.add_char buf ' '; incr i;
        while !i < len && src.[!i] <> '"' do
          if src.[!i] = '\\' && !i + 1 < len then
            (Buffer.add_char buf ' '; incr i;
             Buffer.add_char buf ' '; incr i)
          else (Buffer.add_char buf ' '; incr i)
        done;
        if !i < len then (Buffer.add_char buf ' '; incr i)
      end
      else begin Buffer.add_char buf c; incr i end
    end else begin Buffer.add_char buf c; incr i end
  done;
  Buffer.contents buf

(* Rust keyword filter *)
let is_rust_keyword w =
  List.mem w ["if"; "else"; "for"; "while"; "loop"; "match"; "return";
              "let"; "mut"; "ref"; "const"; "static"; "type"; "struct";
              "enum"; "trait"; "impl"; "fn"; "pub"; "use"; "mod"; "crate";
              "self"; "Self"; "super"; "where"; "as"; "in"; "unsafe";
              "async"; "await"; "move"; "dyn"; "Box"; "Vec"; "Option";
              "Result"; "Some"; "None"; "Ok"; "Err"; "true"; "false";
              "break"; "continue"; "extern"]

(* Crypto operation detection *)
let crypto_patterns = [
  (Str.regexp {|scalar_mul\|scalar_mult\|basepoint_mul|}, "scalar_mul");
  (Str.regexp {|EdwardsPoint\|RistrettoPoint\|CompressedEdwardsY|}, "curve_point");
  (Str.regexp {|Scalar::\|scalar_from\|Scalar\.from|}, "scalar_op");
  (Str.regexp {|hash_to_scalar\|Keccak256\|keccak256\|Blake2b|}, "hash");
  (Str.regexp {|sign\|Sign\|signature\|Signature|}, "sign");
  (Str.regexp {|verify\|Verify\|verification|}, "verify");
  (Str.regexp {|key_image\|KeyImage\|key_img|}, "key_image");
  (Str.regexp {|ring_sig\|RingSig\|clsag\|Clsag\|CLSAG|}, "ring_sig");
  (Str.regexp {|bulletproof\|Bulletproof\|range_proof\|RangeProof|}, "range_proof");
  (Str.regexp {|commitment\|Commitment\|pedersen\|Pedersen|}, "commitment");
  (Str.regexp {|blinding\|blind_factor\|mask|}, "blinding");
  (Str.regexp {|varint\|VarInt\|read_varint\|write_varint|}, "varint");
  (Str.regexp {|amount_decode\|amount_encode\|ecdhDecode|}, "amount_codec");
  (Str.regexp {|view_key\|spend_key\|ViewKey\|SpendKey|}, "key_material");
  (Str.regexp {|subaddress\|Subaddress\|SubAddress|}, "subaddress");
  (Str.regexp {|output_key\|one_time_key\|stealth|}, "stealth_addr");
]

(* Sink detection for Rust *)
let sink_patterns = [
  (Str.regexp {|panic!\|todo!\|unimplemented!\|unreachable!|}, "panic_macro");
  (Str.regexp {|\.unwrap()\|\.expect(|}, "unwrap");
  (Str.regexp {|unsafe[ \t]*{|}, "unsafe_block");
  (Str.regexp {|transmute\|from_raw_parts\|as_mut_ptr|}, "unsafe_cast");
  (Str.regexp {|std::process::exit\|abort()|}, "abort");
  (Str.regexp {|\[.*\][ \t]*=\|get_unchecked|}, "unchecked_index");
  (Str.regexp {|as u8\|as u16\|as u32\|as u64\|as i|}, "truncating_cast");
  (Str.regexp {|from_bytes_unchecked\|from_utf8_unchecked|}, "unchecked_conv");
]

let find_patterns patterns content =
  List.fold_left (fun acc (re, label) ->
    if (try ignore (Str.search_forward re content 0); true
        with Not_found -> false) then label :: acc else acc
  ) [] patterns |> List.rev

let re_pub_fn = Str.regexp {|pub\([ \t]*(crate\|super)\)?[ \t]+\(unsafe[ \t]+\)?fn[ \t]+\([a-zA-Z_][a-zA-Z0-9_]*\)|}
let re_fn = Str.regexp {|\(pub\([ \t]*(crate\|super)\)?[ \t]+\)?\(unsafe[ \t]+\)?fn[ \t]+\([a-zA-Z_][a-zA-Z0-9_]*\)|}
let re_impl = Str.regexp {|impl\(<[^>]*>\)?[ \t]+\([A-Za-z_][A-Za-z0-9_:]*\)[ \t]+for[ \t]+\([A-Za-z_][A-Za-z0-9_:]*\)|}
let re_impl_bare = Str.regexp {|impl\(<[^>]*>\)?[ \t]+\([A-Za-z_][A-Za-z0-9_:]*\)[ \t]*{|}
let re_mod = Str.regexp {|mod[ \t]+\([a-zA-Z_][a-zA-Z0-9_]*\)|}

let parse_rust_file path =
  let ic = open_in path in
  let raw = really_input_string ic (in_channel_length ic) in
  close_in ic;
  let content = strip_rust_comments_and_strings raw in
  let lines = String.split_on_char '\n' content in
  let endpoints = ref [] in
  let current_mod = ref "" in
  let current_impl = ref "" in
  let current_trait = ref "" in
  let impl_depth = ref 0 in
  let in_fn = ref false in
  let fn_depth = ref 0 in
  let fn_buf = Buffer.create 512 in
  let fn_name = ref "" in
  let fn_vis = ref "" in
  let fn_unsafe = ref false in
  let fn_line = ref 0 in
  let depth = ref 0 in
  List.iteri (fun i line ->
    (* Track module *)
    (try ignore (Str.search_forward re_mod line 0);
      current_mod := Str.matched_group 1 line
    with Not_found -> ());
    (* Track impl blocks *)
    if not !in_fn then begin
      (try ignore (Str.search_forward re_impl line 0);
        current_trait := (try Str.matched_group 2 line with _ -> "");
        current_impl := (try Str.matched_group 3 line with _ -> "");
        impl_depth := !depth
      with Not_found ->
        (try ignore (Str.search_forward re_impl_bare line 0);
          current_impl := (try Str.matched_group 2 line with _ -> "");
          current_trait := "";
          impl_depth := !depth
        with Not_found -> ()))
    end;
    (* Track function starts *)
    if not !in_fn then begin
      let has_fn = try ignore (Str.search_forward re_fn line 0); true
        with Not_found -> false in
      if has_fn then begin
        in_fn := true;
        fn_depth := 0;
        fn_line := i + 1;
        Buffer.clear fn_buf;
        (* Determine visibility *)
        fn_vis := (if try ignore (Str.search_forward (Str.regexp "pub") line 0); true
                   with Not_found -> false then "pub" else "private");
        fn_unsafe := (try ignore (Str.search_forward (Str.regexp "unsafe") line 0); true
                      with Not_found -> false);
        fn_name := (try
          ignore (Str.search_forward (Str.regexp {|fn[ \t]+\([a-zA-Z_][a-zA-Z0-9_]*\)|}) line 0);
          Str.matched_group 1 line with Not_found -> "unknown");
      end
    end;
    (* Accumulate function body *)
    if !in_fn then begin
      Buffer.add_string fn_buf line;
      Buffer.add_char fn_buf '\n';
      String.iter (fun c -> match c with
        | '{' -> incr fn_depth | '}' -> decr fn_depth | _ -> ()) line;
      if !fn_depth <= 0 && (String.contains line '{' || i > !fn_line) then begin
        (* Function complete - analyze *)
        let body = Buffer.contents fn_buf in
        let crypto_ops = find_patterns crypto_patterns body in
        let sinks = find_patterns sink_patterns body in
        let unsafe_count =
          let re = Str.regexp {|unsafe[ \t]*{|} in
          let c = ref 0 in let s = ref 0 in
          (try while true do
            ignore (Str.search_forward re body !s);
            incr c; s := Str.match_end ()
          done with Not_found -> ()); !c in
        (* Extract callees - function calls that aren't keywords *)
        let callees = ref [] in
        let re_call = Str.regexp {|\([a-zA-Z_][a-zA-Z0-9_:]*\)(|} in
        let start = ref 0 in
        (try while true do
          ignore (Str.search_forward re_call body !start);
          let name = Str.matched_group 1 body in
          if not (is_rust_keyword name) && not (List.mem name !callees) then
            callees := name :: !callees;
          start := Str.match_end ()
        done with Not_found -> ());
        let module_path = if !current_impl <> "" then
          !current_mod ^ "::" ^ !current_impl
        else !current_mod in
        endpoints := {
          file = path; module_path; name = !fn_name;
          kind = (if !fn_unsafe then "unsafe_fn"
                  else if !current_trait <> "" then "trait_impl"
                  else "fn");
          visibility = !fn_vis;
          is_unsafe = !fn_unsafe;
          is_async = (try ignore (Str.search_forward (Str.regexp "async") body 0); true
                      with Not_found -> false);
          generics = [];
          params = [];
          returns = "";
          traits_impl = (if !current_trait <> "" then [!current_trait] else []);
          unsafe_blocks = unsafe_count;
          crypto_ops; sinks;
          state_reads = []; state_writes = [];
          callees = List.rev !callees;
        } :: !endpoints;
        in_fn := false
      end
    end;
    (* Track brace depth for impl block exit *)
    String.iter (fun c -> match c with
      | '{' -> incr depth | '}' -> decr depth | _ -> ()) line;
    if !depth <= !impl_depth && !impl_depth > 0 then begin
      current_impl := ""; current_trait := ""; impl_depth := 0
    end
  ) lines;
  List.rev !endpoints

let scan_directory dir =
  let endpoints = ref [] in
  let rec walk d =
    let entries = try Sys.readdir d with _ -> [||] in
    Array.iter (fun e ->
      let path = Filename.concat d e in
      if Sys.is_directory path then
        (if e <> "target" && e <> ".git" && e <> "node_modules" then walk path)
      else if Filename.check_suffix e ".rs" then
        (try endpoints := parse_rust_file path @ !endpoints with _ -> ())
      else ()
    ) entries
  in
  walk dir;
  !endpoints

(* ═══════════════════════════════════════════════════════════════════
   PART 2: VULNERABILITY SCANNER (replaces opaca_vigolium for Rust/Crypto)
   Models what real tools detect:
   - dudect/timecop: constant-time violations
   - MIRI: undefined behavior in unsafe
   - cargo-fuzz: panic paths
   - Kani: formal property violations
   - Manual audit: crypto invariant breaks
   ═══════════════════════════════════════════════════════════════════ *)

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

(* --- Detector: Constant-time violations (models dudect/timecop) --- *)
(* Secret-dependent branches and indexing are the #1 crypto bug class *)
let detect_ct_violations _file content =
  let lines = String.split_on_char '\n' content in
  let findings = ref [] in
  let in_crypto_fn = ref false in
  let crypto_fn_depth = ref 0 in
  List.iteri (fun i line ->
    (* Are we inside a function that handles key material? *)
    if (try ignore (Str.search_forward
      (Str.regexp {|fn.*\(key\|secret\|scalar\|private\|blind\|mask\|nonce\)|}
      ) line 0); true with Not_found -> false) then begin
      in_crypto_fn := true; crypto_fn_depth := 0
    end;
    if !in_crypto_fn then begin
      String.iter (fun c -> match c with
        | '{' -> incr crypto_fn_depth | '}' -> decr crypto_fn_depth | _ -> ()) line;
      (* Secret-dependent branch *)
      if (try ignore (Str.search_forward
        (Str.regexp {|if.*\(secret\|key\|scalar\|private\|blind\)|}) line 0); true
        with Not_found -> false) then
        findings := (i+1, Probable,
          "Secret-dependent branch in crypto function - timing side-channel") :: !findings;
      (* Secret-dependent array index *)
      if (try ignore (Str.search_forward
        (Str.regexp {|\[.*\(secret\|key\|scalar\|private\)\]|}) line 0); true
        with Not_found -> false) then
        findings := (i+1, Probable,
          "Secret-dependent array index - possible cache timing oracle (name-based, verify)") :: !findings;
      (* Early return on secret *)
      if (try ignore (Str.search_forward
        (Str.regexp {|return.*\(secret\|key\|scalar\|private\)|}) line 0); true
        with Not_found -> false) then
        findings := (i+1, Probable,
          "Early return dependent on secret value - timing leak") :: !findings;
      (* Division by secret (variable-time on most architectures) *)
      if (try ignore (Str.search_forward
        (Str.regexp {|/ *\(secret\|key\|scalar\|private\|self\.\)|}) line 0); true
        with Not_found -> false) then
        findings := (i+1, Probable,
          "Division on secret value - variable-time (name-based, verify operand is truly secret)") :: !findings;
      if !crypto_fn_depth <= 0 then in_crypto_fn := false
    end
  ) lines;
  !findings

(* --- Detector: Panic paths from public API (models cargo-fuzz/MIRI) --- *)
let detect_panic_paths _file content =
  let lines = String.split_on_char '\n' content in
  let findings = ref [] in
  let in_pub_fn = ref false in
  let pub_depth = ref 0 in
  List.iteri (fun i line ->
    if (try ignore (Str.search_forward (Str.regexp {|pub.*fn |}) line 0); true
        with Not_found -> false) then begin
      in_pub_fn := true; pub_depth := 0
    end;
    if !in_pub_fn then begin
      String.iter (fun c -> match c with
        | '{' -> incr pub_depth | '}' -> decr pub_depth | _ -> ()) line;
      (* unwrap/expect without prior check *)
      if (try ignore (Str.search_forward
        (Str.regexp {|\.unwrap()\|\.expect(|}) line 0); true
        with Not_found -> false) then
        findings := (i+1, Theoretical,
          "unwrap/expect in pub fn - LEAD ONLY, reachability from untrusted input unproven") :: !findings;
      (* Direct indexing without bounds check *)
      if (try ignore (Str.search_forward
        (Str.regexp {|\[[a-zA-Z_][a-zA-Z0-9_]*\]|}) line 0); true
        with Not_found -> false) &&
        not (try ignore (Str.search_forward (Str.regexp {|get(\|get_unchecked|}) line 0); true
             with Not_found -> false) then
        findings := (i+1, Theoretical,
          "Direct indexing in public function - potential panic on OOB") :: !findings;
      (* Explicit panic/todo/unimplemented *)
      if (try ignore (Str.search_forward
        (Str.regexp {|panic!\|todo!\|unimplemented!|}) line 0); true
        with Not_found -> false) then
        findings := (i+1, Theoretical,
          "panic!/todo! in pub fn - LEAD ONLY, not a DoS unless reachable from an untrusted (deserialize/verify) entry point") :: !findings;
      if !pub_depth <= 0 then in_pub_fn := false
    end
  ) lines;
  !findings

(* --- Detector: Unsafe soundness (models MIRI) --- *)
let detect_unsafe_issues _file content =
  let lines = String.split_on_char '\n' content in
  let findings = ref [] in
  let in_unsafe = ref false in
  let unsafe_depth = ref 0 in
  List.iteri (fun i line ->
    if (try ignore (Str.search_forward (Str.regexp {|unsafe[ \t]*{|}) line 0); true
        with Not_found -> false) then begin
      in_unsafe := true; unsafe_depth := 0
    end;
    if !in_unsafe then begin
      String.iter (fun c -> match c with
        | '{' -> incr unsafe_depth | '}' -> decr unsafe_depth | _ -> ()) line;
      (* transmute without size assertion *)
      if (try ignore (Str.search_forward (Str.regexp "transmute") line 0); true
          with Not_found -> false) then
        findings := (i+1, Probable,
          "transmute in unsafe block - verify type sizes match") :: !findings;
      (* from_raw_parts without length validation *)
      if (try ignore (Str.search_forward (Str.regexp "from_raw_parts") line 0); true
          with Not_found -> false) then
        findings := (i+1, Probable,
          "from_raw_parts - verify pointer validity and length") :: !findings;
      (* Pointer arithmetic *)
      if (try ignore (Str.search_forward (Str.regexp {|\.offset(\|\.add(\|\.sub(|}) line 0); true
          with Not_found -> false) then
        findings := (i+1, Theoretical,
          "Pointer arithmetic in unsafe - verify bounds") :: !findings;
      if !unsafe_depth <= 0 then in_unsafe := false
    end
  ) lines;
  !findings

(* --- Detector: Crypto invariant violations (models manual audit) --- *)
let detect_crypto_invariants _file content =
  let lines = String.split_on_char '\n' content in
  let findings = ref [] in
  List.iteri (fun i line ->
    (* Scalar not reduced mod l *)
    if (try ignore (Str.search_forward
      (Str.regexp {|Scalar::from_bytes\|from_bytes_mod_order|}) line 0); true
      with Not_found -> false) &&
      not (try ignore (Str.search_forward (Str.regexp "reduce\|mod_order\|canonical") line 0); true
           with Not_found -> false) then
      findings := (i+1, Probable,
        "Scalar from bytes without explicit reduction check - may accept non-canonical") :: !findings;
    (* Point not on curve check *)
    if (try ignore (Str.search_forward
      (Str.regexp {|decompress\|from_bytes\|CompressedEdwardsY|}) line 0); true
      with Not_found -> false) &&
      (try ignore (Str.search_forward (Str.regexp {|is_some\|is_ok\|?\||}) line 0); true
       with Not_found -> false) &&
      not (try ignore (Str.search_forward (Str.regexp "is_torsion_free\|is_identity") line 0); true
           with Not_found -> false) then
      findings := (i+1, Theoretical,
        "Point decompression without torsion/identity check") :: !findings;
    (* Key image computation without cofactor *)
    if (try ignore (Str.search_forward (Str.regexp "key_image\|KeyImage") line 0); true
        with Not_found -> false) &&
      not (try ignore (Str.search_forward (Str.regexp "mul_by_cofactor\|cofactor") line 0); true
           with Not_found -> false) then
      findings := (i+1, Probable,
        "Key image computation - verify cofactor multiplication") :: !findings;
    (* Nonce generation without domain separation *)
    if (try ignore (Str.search_forward (Str.regexp {|nonce\|Nonce|}) line 0); true
        with Not_found -> false) &&
      (try ignore (Str.search_forward (Str.regexp "random\|rand\|Rng") line 0); true
       with Not_found -> false) &&
      not (try ignore (Str.search_forward (Str.regexp "domain\|separator\|tag") line 0); true
           with Not_found -> false) then
      findings := (i+1, Theoretical,
        "Nonce generation without domain separation - potential reuse across contexts") :: !findings;
    (* Commitment without blinding factor validation *)
    if (try ignore (Str.search_forward (Str.regexp "Commitment\|commitment\|pedersen") line 0); true
        with Not_found -> false) &&
      (try ignore (Str.search_forward (Str.regexp "amount\|value") line 0); true
       with Not_found -> false) &&
      not (try ignore (Str.search_forward (Str.regexp "range_proof\|bulletproof\|verify") line 0); true
           with Not_found -> false) then
      findings := (i+1, Probable,
        "Commitment construction without associated range proof verification") :: !findings;
  ) lines;
  !findings

(* --- Detector: Consensus divergence patterns --- *)
let detect_consensus_divergence _file content =
  let lines = String.split_on_char '\n' content in
  let findings = ref [] in
  List.iteri (fun i line ->
    (* Varint encoding differences *)
    if (try ignore (Str.search_forward (Str.regexp {|varint\|VarInt|}) line 0); true
        with Not_found -> false) &&
      (try ignore (Str.search_forward (Str.regexp {|as u\|as i\|try_into\|from(|}) line 0); true
       with Not_found -> false) then
      findings := (i+1, Theoretical,
        "VarInt with type cast - verify matches C++ reference encoding exactly") :: !findings;
    (* Truncating casts in consensus code *)
    if (try ignore (Str.search_forward
      (Str.regexp {|as u8\|as u16\|as u32\|as i32|}) line 0); true
      with Not_found -> false) &&
      (try ignore (Str.search_forward
        (Str.regexp {|amount\|height\|timestamp\|difficulty\|weight|}) line 0); true
       with Not_found -> false) then
      findings := (i+1, Probable,
        "Truncating cast on consensus field - may diverge from C++ behavior on overflow") :: !findings;
    (* Serialization order sensitivity *)
    if (try ignore (Str.search_forward (Str.regexp {|serialize\|Serialize\|to_bytes|}) line 0); true
        with Not_found -> false) &&
      (try ignore (Str.search_forward (Str.regexp {|HashMap\|BTreeMap\|HashSet|}) line 0); true
       with Not_found -> false) then
      findings := (i+1, Probable,
        "Serialization of unordered collection - non-deterministic byte output") :: !findings;
    (* Integer overflow behavior difference *)
    if (try ignore (Str.search_forward
      (Str.regexp {|wrapping_\|saturating_\|checked_\|overflowing_|}) line 0); true
      with Not_found -> false) then
      findings := (i+1, Theoretical,
        "Explicit overflow handling - verify matches C++ wrapping semantics") :: !findings;
  ) lines;
  !findings

(* --- Detector: Integer overflow under overflow-checks=true --- *)
let detect_overflow_abort _file content =
  let lines = String.split_on_char '\n' content in
  let findings = ref [] in
  let in_pub_fn = ref false in
  let pub_depth = ref 0 in
  List.iteri (fun i line ->
    if (try ignore (Str.search_forward (Str.regexp {|pub.*fn |}) line 0); true
        with Not_found -> false) then begin
      in_pub_fn := true; pub_depth := 0
    end;
    if !in_pub_fn then begin
      String.iter (fun c -> match c with
        | '{' -> incr pub_depth | '}' -> decr pub_depth | _ -> ()) line;
      (* Arithmetic on user-controlled values without checked_ *)
      if (try ignore (Str.search_forward (Str.regexp {|[+\-*]|}) line 0); true
          with Not_found -> false) &&
        (try ignore (Str.search_forward
          (Str.regexp {|amount\|fee\|size\|len\|count\|height\|weight|}) line 0); true
         with Not_found -> false) &&
        not (try ignore (Str.search_forward
          (Str.regexp {|checked_\|saturating_\|wrapping_|}) line 0); true
             with Not_found -> false) then
        findings := (i+1, Theoretical,
          "Arithmetic on user-controlled value without checked_ - abort on overflow (DoS)") :: !findings;
      if !pub_depth <= 0 then in_pub_fn := false
    end
  ) lines;
  !findings

(* All detectors *)
type detector = {
  id : string;
  title : string;
  sev : severity;
  detect : string -> string -> (int * confidence * string) list;
}

let all_detectors = [
  { id = "constant-time"; title = "Constant-Time Violation";
    sev = Critical; detect = detect_ct_violations };
  { id = "panic-path"; title = "Reachable Panic (DoS)";
    sev = Medium; detect = detect_panic_paths };
  { id = "unsafe-soundness"; title = "Unsafe Soundness Issue";
    sev = High; detect = detect_unsafe_issues };
  { id = "crypto-invariant"; title = "Cryptographic Invariant Violation";
    sev = Critical; detect = detect_crypto_invariants };
  { id = "consensus-divergence"; title = "Consensus Divergence";
    sev = High; detect = detect_consensus_divergence };
  { id = "overflow-abort"; title = "Overflow-Induced Abort";
    sev = Medium; detect = detect_overflow_abort };
]

let scan_file path =
  let ic = open_in path in
  let content = really_input_string ic (in_channel_length ic) in
  close_in ic;
  let stripped = strip_rust_comments_and_strings content in
  let findings = ref [] in
  List.iter (fun det ->
    let hits = det.detect path stripped in
    List.iter (fun (line, conf, desc) ->
      (* INVARIANT: a lexical/pattern scanner produces LEADS, never proof.
         Confirmed is reserved for findings carrying an external evidence
         artifact (compiling PoC + reachability trace), attached downstream.
         So clamp anything a detector claims as Confirmed down to Probable. *)
      let conf = match conf with Confirmed -> Probable | c -> c in
      findings := {
        title = det.title; severity = det.sev; confidence = conf;
        file = path; line; pattern = det.id; description = desc;
      } :: !findings
    ) hits
  ) all_detectors;
  List.rev !findings

let scan_directory_findings dir =
  let findings = ref [] in
  let rec walk d =
    let entries = try Sys.readdir d with _ -> [||] in
    Array.iter (fun e ->
      let path = Filename.concat d e in
      if Sys.is_directory path then
        (if e <> "target" && e <> ".git" && e <> "node_modules" then walk path)
      else if Filename.check_suffix e ".rs" then
        (try findings := scan_file path @ !findings with _ -> ())
      else ()
    ) entries
  in
  walk dir;
  !findings

(* ═══════════════════════════════════════════════════════════════════
   PART 3: UNIFIED INTERFACE (same shape as opaca_noir + opaca_vigolium)
   ═══════════════════════════════════════════════════════════════════ *)

let endpoint_to_json (ep : endpoint) =
  let list_to_json l = "[" ^ String.concat "," (List.map (Printf.sprintf "%S") l) ^ "]" in
  Printf.sprintf
    {|{"file":%S,"module_path":%S,"name":%S,"kind":%S,"visibility":%S,"is_unsafe":%b,"unsafe_blocks":%d,"crypto_ops":%s,"callees":%s,"sinks":%s,"traits_impl":%s}|}
    ep.file ep.module_path ep.name ep.kind ep.visibility
    ep.is_unsafe ep.unsafe_blocks
    (list_to_json ep.crypto_ops) (list_to_json ep.callees)
    (list_to_json ep.sinks) (list_to_json ep.traits_impl)

let finding_to_json (f : finding) =
  Printf.sprintf
    {|{"title":%S,"severity":%S,"confidence":%S,"file":%S,"line":%d,"pattern":%S,"description":%S}|}
    f.title (sev_to_string f.severity) (conf_to_string f.confidence)
    f.file f.line f.pattern f.description

let run_surface dir output_path =
  let eps = scan_directory dir in
  let json = "[" ^ String.concat ",\n" (List.map endpoint_to_json eps) ^ "]" in
  let oc = open_out output_path in
  output_string oc json;
  close_out oc;
  eps

let run_findings dir output_path =
  let fs = scan_directory_findings dir in
  let json = "{\"findings\":[" ^
    String.concat ",\n" (List.map finding_to_json fs) ^ "]}" in
  let oc = open_out output_path in
  output_string oc json;
  close_out oc;
  fs
