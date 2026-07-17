(* toolchain.ml - ecosystem dispatcher.
   Detects target language and routes to appropriate toolchain.
   Each toolchain provides:
   - surface mapping (endpoints)
   - vulnerability scanning (findings)
   Same output shape regardless of ecosystem. *)

type ecosystem =
  | EVM        (* Solidity/Vyper - smart contracts *)
  | Monero     (* Rust/C++ - crypto protocol *)
  | Solana     (* Rust/Anchor - programs *)
  | Move       (* Move - Aptos/Sui *)
  | Bitcoin    (* C++/Rust - consensus/Lightning *)
  | Cosmos     (* Go - IBC/modules *)
  | Unknown

let detect_ecosystem dir =
  let has_ext ext =
    let found = ref false in
    let rec walk d =
      if !found then () else
      let entries = try Sys.readdir d with _ -> [||] in
      Array.iter (fun e ->
        if !found then () else
        let path = Filename.concat d e in
        if Sys.is_directory path then
          (if e <> "target" && e <> ".git" && e <> "node_modules"
              && e <> "lib" && e <> "build" then walk path)
        else if Filename.check_suffix e ext then found := true
      ) entries
    in walk dir; !found in
  let has_file name =
    let found = ref false in
    let rec walk d =
      if !found then () else
      let entries = try Sys.readdir d with _ -> [||] in
      Array.iter (fun e ->
        if !found then () else
        let path = Filename.concat d e in
        if Sys.is_directory path then
          (if e <> "target" && e <> ".git" then walk path)
        else if e = name then found := true
      ) entries
    in walk dir; !found in
  (* Detection heuristics *)
  if has_ext ".sol" then EVM
  else if has_file "Cargo.toml" then begin
    (* Distinguish Rust ecosystems by dependencies *)
    let cargo_content = ref "" in
    let rec find_cargo d =
      let entries = try Sys.readdir d with _ -> [||] in
      Array.iter (fun e ->
        let path = Filename.concat d e in
        if e = "Cargo.toml" && !cargo_content = "" then begin
          let ic = open_in path in
          cargo_content := really_input_string ic (in_channel_length ic);
          close_in ic
        end else if Sys.is_directory path && e <> "target" && e <> ".git" then
          find_cargo path
      ) entries
    in find_cargo dir;
    let c = !cargo_content in
    if (try ignore (Str.search_forward
      (Str.regexp {|monero\|dalek\|curve25519\|bulletproofs\|clsag|}) c 0); true
      with Not_found -> false) then Monero
    else if (try ignore (Str.search_forward
      (Str.regexp {|anchor\|solana\|spl-token\|borsh|}) c 0); true
      with Not_found -> false) then Solana
    else Monero  (* default Rust to Monero for this bounty context *)
  end
  else if has_ext ".move" then Move
  else if has_ext ".go" && has_file "go.mod" then Cosmos
  else if has_ext ".cpp" || has_ext ".cc" then begin
    (* C++ could be Bitcoin or Monero *)
    let has_monero = has_file "cryptonote_core" || has_file "ringct" in
    let has_bitcoin = has_file "consensus" || has_file "script.cpp" in
    if has_monero then Monero
    else if has_bitcoin then Bitcoin
    else Monero  (* default *)
  end
  else Unknown

let ecosystem_to_string = function
  | EVM -> "evm" | Monero -> "monero" | Solana -> "solana"
  | Move -> "move" | Bitcoin -> "bitcoin" | Cosmos -> "cosmos"
  | Unknown -> "unknown"
