(* witness_actor.ml — SHA256 append-only witness chain *)

let chain : Msg.witness_entry list ref = ref []

let record phase data =
  let prev = match !chain with
    | [] -> String.make 64 '0'
    | hd :: _ -> hd.sha256
  in
  let hash = Shell.sha256 (prev ^ "|" ^ phase ^ "|" ^ data) in
  let entry = Msg.{ phase; sha256 = hash; epoch = Unix.gettimeofday () } in
  chain := entry :: !chain; entry

let dump () =
  List.rev !chain
  |> List.map (fun (e : Msg.witness_entry) ->
    Printf.sprintf "%.0f|%s|%s" e.epoch e.phase e.sha256)
  |> String.concat "\n"
