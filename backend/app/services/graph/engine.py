import networkx as nx
from typing import List, Dict, Any, Tuple

class AttackGraphEngine:
    def __init__(self):
        self.graph = nx.DiGraph()

    def build_graph(
        self, 
        assets: List[Dict[str, Any]], 
        relationships: List[Dict[str, Any]],
        findings: List[Dict[str, Any]]
    ):
        """
        Constructs directed graph from persisted tenant state.
        """
        self.graph.clear()
        
        # Add Asset Nodes
        for a in assets:
            self.graph.add_node(
                a["id"],
                node_type="ASSET",
                hostname=a.get("hostname", "unknown"),
                exposure=a.get("exposure", "INTERNAL"),
                criticality=a.get("criticality", "MEDIUM"),
                environment=a.get("environment", "production")
            )
            
        # Add Finding Nodes and edges (Asset -> Finding)
        for f in findings:
            f_node_id = f"VULN:{f['id']}"
            self.graph.add_node(
                f_node_id,
                node_type="VULNERABILITY",
                cve_id=f.get("cve_id"),
                priority=f.get("contextual_priority"),
                status=f.get("status")
            )
            # Host edge
            self.graph.add_edge(
                a["id"] if (a := next((x for x in assets if x["id"] == f["asset_id"]), None)) else f["asset_id"],
                f_node_id,
                rel_type="HOSTS_VULNERABILITY",
                state="VERIFIED"
            )

        # Add Asset Relationships (Network/Identity Edges)
        for rel in relationships:
            self.graph.add_edge(
                rel["source_asset_id"],
                rel["target_asset_id"],
                edge_id=rel.get("id"),
                rel_type=rel.get("relationship_type", "CAN_ACCESS"),
                state=rel.get("state", "UNKNOWN"),
                port=rel.get("port"),
                protocol=rel.get("protocol")
            )

    def find_attack_paths(
        self, 
        entry_exposure: str = "INTERNET_FACING",
        target_criticality: str = "MISSION_CRITICAL",
        max_depth: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Computes all simple bounded paths from perimeter entry points to high-value assets.
        """
        entry_nodes = [
            n for n, d in self.graph.nodes(data=True)
            if d.get("node_type") == "ASSET" and d.get("exposure") == entry_exposure
        ]
        target_nodes = [
            n for n, d in self.graph.nodes(data=True)
            if d.get("node_type") == "ASSET" and d.get("criticality") == target_criticality
        ]

        discovered_paths = []
        for entry in entry_nodes:
            for target in target_nodes:
                if entry == target:
                    continue
                if nx.has_path(self.graph, entry, target):
                    for path in nx.all_simple_paths(self.graph, entry, target, cutoff=max_depth):
                        evaluated = self._evaluate_path(path)
                        discovered_paths.append(evaluated)

        # Sort by verified ratio (descending)
        return sorted(discovered_paths, key=lambda x: x["verified_edge_ratio"], reverse=True)

    def _evaluate_path(self, path: List[str]) -> Dict[str, Any]:
        hops = []
        verified_count = 0
        unknown_count = 0

        for i in range(len(path) - 1):
            u, v = path[i], path[i+1]
            edge_data = self.graph.get_edge_data(u, v) or {}
            state = edge_data.get("state", "UNKNOWN")
            if state == "VERIFIED":
                verified_count += 1
            else:
                unknown_count += 1

            u_node = self.graph.nodes[u]
            v_node = self.graph.nodes[v]

            hops.append({
                "step_number": i + 1,
                "source_asset_id": u,
                "source_hostname": u_node.get("hostname", u),
                "target_asset_id": v,
                "target_hostname": v_node.get("hostname", v),
                "relationship_type": edge_data.get("rel_type", "CAN_ACCESS"),
                "port": edge_data.get("port"),
                "state": state,
                "prerequisites": ["Network reachability confirmed"] if state == "VERIFIED" else ["Unverified route"]
            })

        total = len(hops)
        ratio = verified_count / total if total > 0 else 0.0

        if ratio == 1.0:
            tier = "VERIFIED_CHAIN"
        elif ratio >= 0.5:
            tier = "PLAUSIBLE_HYPOTHESIS"
        else:
            tier = "UNVERIFIED_PATH"

        entry_node = self.graph.nodes[path[0]]
        target_node = self.graph.nodes[path[-1]]

        return {
            "path_id": f"PATH-{path[0][:6]}-{path[-1][:6]}-{len(path)}",
            "entry_asset": entry_node.get("hostname", path[0]),
            "target_asset": target_node.get("hostname", path[-1]),
            "target_criticality": target_node.get("criticality", "MEDIUM"),
            "path_length": total,
            "verified_edge_ratio": round(ratio, 2),
            "feasibility_tier": tier,
            "has_unverified_hops": unknown_count > 0,
            "hops": hops,
            "mitigating_controls": ["Firewall Egress Rule", "Network Segmentation"] if unknown_count > 0 else []
        }

    def simulate_counterfactual_remediation(
        self,
        sever_relationship_ids: List[str],
        remediate_cves: List[str],
        entry_exposure: str = "INTERNET_FACING",
        target_criticality: str = "MISSION_CRITICAL"
    ) -> Dict[str, Any]:
        """
        Simulates what-if scenarios without modifying production state.
        """
        initial_paths = self.find_attack_paths(entry_exposure, target_criticality)
        
        # Clone graph
        sim_graph = self.graph.copy()

        # Remove severed edges
        for u, v, data in list(sim_graph.edges(data=True)):
            if data.get("edge_id") in sever_relationship_ids:
                sim_graph.remove_edge(u, v)

        # Remove remediated vulnerability nodes and their connected edges
        for node, data in list(sim_graph.nodes(data=True)):
            if data.get("node_type") == "VULNERABILITY" and data.get("cve_id") in remediate_cves:
                sim_graph.remove_node(node)

        # Temporary swap to compute residual paths
        original_graph = self.graph
        self.graph = sim_graph
        residual_paths = self.find_attack_paths(entry_exposure, target_criticality)
        self.graph = original_graph

        severed_count = len(initial_paths) - len(residual_paths)
        
        recommendations = []
        if severed_count > 0:
            recommendations.append(f"Applying these changes severs {severed_count} active attack path(s) reaching critical assets.")
        else:
            recommendations.append("Proposed remediation does not break existing reachable paths to crown jewels.")

        return {
            "initial_critical_paths_count": len(initial_paths),
            "residual_critical_paths_count": len(residual_paths),
            "severed_paths_count": max(severed_count, 0),
            "remediated_findings_count": len(remediate_cves),
            "severed_path_details": [p for p in initial_paths if p["path_id"] not in [r["path_id"] for r in residual_paths]],
            "recommendations": recommendations
        }

attack_graph_engine = AttackGraphEngine()
