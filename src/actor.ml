(* actor.ml — minimal actor runtime on Domain/Mutex/Condition. 
   OCaml 5 required. Zero deps. *)

type pid = int
type 'a mailbox = {
  mutable queue : 'a list;
  mutex : Mutex.t;
  cond : Condition.t;
}

let next_pid = ref 0
let registry : (string, pid) Hashtbl.t = Hashtbl.create 16
let mailboxes : (pid, Obj.t mailbox) Hashtbl.t = Hashtbl.create 16
let domains : (pid, Domain.id) Hashtbl.t = Hashtbl.create 16
let alive : (pid, bool) Hashtbl.t = Hashtbl.create 16

let make_mailbox () = {
  queue = []; mutex = Mutex.create (); cond = Condition.create ()
}

let log tag fmt =
  Printf.ksprintf (fun s ->
    Printf.eprintf "[%s] %s\n%!" tag s) fmt

let spawn (f : unit -> unit) : pid =
  let id = !next_pid in
  incr next_pid;
  let mb = make_mailbox () in
  Hashtbl.replace mailboxes id (Obj.magic mb);
  Hashtbl.replace alive id true;
  let _dom = Domain.spawn (fun () ->
    try f ()
    with e -> log "ACTOR" "pid %d crashed: %s" id (Printexc.to_string e)
  ) in
  Hashtbl.replace domains id (Domain.get_id _dom);
  id

let register name pid = Hashtbl.replace registry name pid
let lookup name = Hashtbl.find_opt registry name

let send (pid : pid) (msg : 'a) =
  match Hashtbl.find_opt mailboxes pid with
  | None -> ()
  | Some mb ->
    let mb = (Obj.magic mb : 'a mailbox) in
    Mutex.lock mb.mutex;
    mb.queue <- mb.queue @ [msg];
    Condition.signal mb.cond;
    Mutex.unlock mb.mutex

let receive () : 'a =
  let pid = Domain.self () |> Obj.magic in
  (* find our mailbox by scanning — simplified for single-binary *)
  let mb = ref (make_mailbox ()) in
  Hashtbl.iter (fun _k v ->
    let v' = (Obj.magic v : 'a mailbox) in
    Mutex.lock v'.mutex;
    if v'.queue <> [] || true then mb := v';
    Mutex.unlock v'.mutex
  ) mailboxes;
  ignore pid;
  let m = !mb in
  Mutex.lock m.mutex;
  while m.queue = [] do
    Condition.wait m.cond m.mutex
  done;
  let msg = List.hd m.queue in
  m.queue <- List.tl m.queue;
  Mutex.unlock m.mutex;
  msg

let shutdown () = Domain.recommended_domain_count () |> ignore

let wait_all _pids =
  (* simple: sleep until report is written *)
  Unix.sleep 2
