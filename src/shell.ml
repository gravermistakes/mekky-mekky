(* shell.ml — shell utilities. sha256, file I/O, command exec *)

let sha256 s =
  let tmp_in = Filename.temp_file "sha_" ".in" in
  let tmp_out = Filename.temp_file "sha_" ".out" in
  let oc = open_out tmp_in in
  output_string oc s; close_out oc;
  let cmd = Printf.sprintf "sha256sum %s | cut -d' ' -f1 > %s" tmp_in tmp_out in
  ignore (Sys.command cmd);
  let ic = open_in tmp_out in
  let hash = try String.trim (input_line ic) with _ -> "0" in
  close_in ic;
  Sys.remove tmp_in; Sys.remove tmp_out;
  hash

let write_file path content =
  let dir = Filename.dirname path in
  ignore (Sys.command (Printf.sprintf "mkdir -p %s" dir));
  let oc = open_out path in
  output_string oc content;
  close_out oc

let read_file path =
  let ic = open_in path in
  let s = really_input_string ic (in_channel_length ic) in
  close_in ic; s

let exec cmd =
  let tmp = Filename.temp_file "exec_" ".out" in
  let exit = Sys.command (Printf.sprintf "%s > %s 2>&1" cmd tmp) in
  let output = try read_file tmp with _ -> "" in
  Sys.remove tmp;
  (exit, output)
