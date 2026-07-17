(* graph_actor.ml — join barrier. merges surface map + findings into attack graph *)

let build_graph (eps : Msg.endpoint list) (fs : Msg.vuln_finding list) : Msg.attack_graph =
  let nodes = ref [] in
  let edges = ref [] in
  (* endpoints become nodes *)
  List.iter (fun (ep : Msg.endpoint) ->
    let id = ep.contract ^ "." ^ ep.name in
    let w = match ep.visibility with
      | "external" -> 1.5 | "public" -> 1.0 | _ -> 0.3 in
    let w = w +. (if ep.sinks <> [] then 2.0 else 0.0) in
    let w = w +. (if ep.modifiers = [] && ep.state_writes <> [] then 1.5 else 0.0) in
    nodes := Msg.{ id; label = ep.name; ntype = "endpoint"; weight = w;
                   file = ep.file; pattern = "" } :: !nodes;
    (* edges from callees *)
    List.iter (fun callee ->
      edges := Msg.{ src = id; dst = callee; flow = 0.0 } :: !edges
    ) ep.callees
  ) eps;
  (* findings become high-weight nodes *)
  List.iteri (fun i (f : Msg.vuln_finding) ->
    let conf_tag = match f.vconfidence with
      | Msg.Confirmed -> "confirmed" | Probable -> "probable" | Theoretical -> "theoretical" in
    let id = Printf.sprintf "vuln_%d_%s_%s" i f.pattern conf_tag in
    let w = match f.vseverity with
      | Msg.Critical -> 5.0 | High -> 4.0 | Medium -> 3.0
      | Low -> 1.5 | Info -> 0.5 in
    let w = w *. (match f.vconfidence with
      | Msg.Confirmed -> 1.0 | Probable -> 0.7 | Theoretical -> 0.3) in
    nodes := Msg.{ id; label = f.title; ntype = "finding"; weight = w;
                   file = f.vfile; pattern = f.pattern } :: !nodes;
    (* link finding to nearest endpoint by file *)
    List.iter (fun (ep : Msg.endpoint) ->
      if ep.file = f.vfile then
        edges := Msg.{ src = ep.contract ^ "." ^ ep.name; dst = id; flow = 0.0 } :: !edges
    ) eps
  ) fs;
  Msg.{ nodes = !nodes; edges = !edges }

let to_json (g : Msg.attack_graph) =
  let node_json (n : Msg.graph_node) =
    Printf.sprintf {|{"id":%S,"label":%S,"type":%S,"weight":%.2f}|}
      n.id n.label n.ntype n.weight in
  let edge_json (e : Msg.graph_edge) =
    Printf.sprintf {|{"src":%S,"dst":%S,"flow":%.2f}|}
      e.src e.dst e.flow in
  Printf.sprintf {|{"nodes":[%s],"edges":[%s]}|}
    (String.concat "," (List.map node_json g.nodes))
    (String.concat "," (List.map edge_json g.edges))
