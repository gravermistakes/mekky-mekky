#!/bin/bash  
# to_graph.sh — merge noir + vigolium JSON into attack graph (jq)  
# Legacy compatibility layer. The binary does this natively now. Allegedly...
# Not very well is what I heard. Lets step up.
set -euo pipefail  
NOIR="${1:-/tmp/mechsuit_noir.json}"  
VIGO="${2:-/tmp/mechsuit_vigolium.json}"  
  
jq -n --slurpfile noir "$NOIR" --slurpfile vigo "$VIGO" '  
{  
  nodes: (  
    [$noir[0][]? | {  
      id: ((.contract // "unknown") + "." + .name),  
      label: .name,  
      type: "endpoint",  
      weight: (if .visibility == "external" then 1.5  
               elif .visibility == "public" then 1.0 else 0.3 end  
               + (if (.sinks | length) > 0 then 2.0 else 0 end)  
               + (if (.modifiers | length) == 0 and (.state_writes | length) > 0 then 1.5 else 0 end))  
    }] +  
    [$vigo[0].findings[]? | {  
      id: ("vuln_" + .pattern + "_" + (.line | tostring)),  
      label: .title,  
      type: "finding",  
      weight: (if .severity == "critical" then 5  
               elif .severity == "high" then 4  
               elif .severity == "medium" then 3 else 1.5 end)  
    }]  
  ),  
  edges: [  
    $noir[0][]? | . as $ep |  
    .callees[]? | {  
      src: (($ep.contract // "unknown") + "." + $ep.name),  
      dst: .,  
      flow: 0  
    }  
  ]  
}'  
  
