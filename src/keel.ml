(* keel.ml — governance kill switch. scope enforcement. *)

let halted = ref false
let halt_reason = ref ""

let check_scope ~allowed_targets target =
  match allowed_targets with
  | [] -> true  (* empty = allow all *)
  | ts -> List.mem target ts

let halt reason =
  halted := true;
  halt_reason := reason;
  Printf.eprintf "[KEEL] HARD STOP: %s\n%!" reason

let is_halted () = !halted
let reason () = !halt_reason
