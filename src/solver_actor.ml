(* solver_actor.ml — push propagation flow ranking. native. no external deps. *)

let rank (g : Msg.attack_graph) : Msg.attack_graph =
  let weights = Hashtbl.create 32 in
  List.iter (fun (n : Msg.graph_node) ->
    Hashtbl.replace weights n.id n.weight) g.nodes;
  (* 5 iterations of push propagation *)
  for _ = 1 to 5 do
    List.iter (fun (e : Msg.graph_edge) ->
      let src_w = try Hashtbl.find weights e.src with Not_found -> 0.0 in
      let dst_w = try Hashtbl.find weights e.dst with Not_found -> 0.0 in
      Hashtbl.replace weights e.dst (dst_w +. src_w *. 0.25)
    ) g.edges
  done;
  let ranked_nodes = List.map (fun (n : Msg.graph_node) ->
    { n with weight = try Hashtbl.find weights n.id with Not_found -> n.weight }
  ) g.nodes in
  let ranked_edges = List.map (fun (e : Msg.graph_edge) ->
    { e with flow = try Hashtbl.find weights e.src with Not_found -> 0.0 }
  ) g.edges in
  let ranked_nodes = List.sort (fun (a : Msg.graph_node) (b : Msg.graph_node) ->
    compare b.weight a.weight) ranked_nodes in
  Msg.{ nodes = ranked_nodes; edges = ranked_edges }
