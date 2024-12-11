#!/usr/bin/env python3

import subprocess
import json
import sys
import re
from tabulate import tabulate
import argparse

def get_kubernetes_resource(resource, crd=False):
    """Fetch Kubernetes resources and return JSON data."""
    try:
        result = subprocess.run(
            ["kubectl", "get", resource, "-A", "-o", "json"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            text=True
        )
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        resource_type = "CRD" if crd else "resource"
        print(f"Error: Failed to fetch {resource_type} '{resource}': {e.stderr.strip()}")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Error: Unable to parse JSON output for {resource}.")
        sys.exit(1)

def get_ingress_info():
    """Parse standard Kubernetes Ingress resources."""
    ingress_data = get_kubernetes_resource("ingress")
    table = []
    
    for item in ingress_data.get("items", []):
        namespace = item.get("metadata", {}).get("namespace", "N/A")
        rules = item.get("spec", {}).get("rules", [])
        
        for rule in rules:
            host = rule.get("host", "N/A")
            
            # Extract the domain from Host(`...`) format
            if host.startswith("Host(`") and host.endswith("`)"):
                host_value = host[6:-2]  # Remove 'Host(`' and '`)'
            else:
                host_value = host  # Use the original host value if not in the Host() format
            
            paths = rule.get("http", {}).get("paths", [])
            for path in paths:
                path_value = path.get("path", "N/A")
                backend_service = path.get("backend", {}).get("service", {}).get("name", "N/A")
                backend_port = path.get("backend", {}).get("service", {}).get("port", {}).get("number", "N/A")
                
                # Add the cleaned host value and path to the table
                table.append([namespace, "Ingress", host_value, path_value, backend_service, backend_port])
    
    return table

def get_ingressroute_info():
    """Parse Traefik-specific IngressRoute CRDs."""
    ingressroute_data = get_kubernetes_resource("ingressroute", crd=True)
    table = []
    
    for item in ingressroute_data.get("items", []):
        namespace = item.get("metadata", {}).get("namespace", "N/A")
        routes = item.get("spec", {}).get("routes", [])
        
        for route in routes:
            match = route.get("match", "N/A")
            path_value = "N/A"
            
            # Handle Host(`...`) format
            if match.startswith("Host(`") and match.endswith("`)"):
                match = match[6:-2]  # Clean the Host value
            # Handle PathPrefix(`...`) and multiple PathPrefixes separated by " || "
            elif "PathPrefix(`" in match:
                path_value = " || ".join([part[12:-2] for part in match.split(" || ")])
                match = "N/A"  # Set match to N/A as this is a path, not a host
            
            services = route.get("services", [])
            for service in services:
                backend_service = service.get("name", "N/A")
                backend_port = service.get("port", "N/A")
                table.append([namespace, "IngressRoute", match, path_value, backend_service, backend_port])
    
    return table


def display_as_markdown(table, headers):
    """Display data as a Markdown table."""
    markdown_table = tabulate(table, headers=headers, tablefmt="github")
    print(markdown_table)

def display_as_json(table, headers):
    """Display data as JSON."""
    json_output = [
        dict(zip(headers, row)) for row in table
    ]
    print(json.dumps(json_output, indent=4))

def main():
    parser = argparse.ArgumentParser(description="Fetch and display Kubernetes Ingress and IngressRoute information.")
    parser.add_argument(
        "--output", "-o", choices=["md", "json"], required=False,
        help="Output format: 'md' for a Markdown table, 'json' for raw JSON."
    )
    args = parser.parse_args()

    print("Fetching Kubernetes Ingress and IngressRoute information from all namespaces...\n")
    ingress_table = get_ingress_info()
    ingressroute_table = get_ingressroute_info()
    combined_table = ingress_table + ingressroute_table

    headers = ["Namespace", "Type", "Host/Match", "Path", "Backend Service", "Port"]

    if args.output == "md":
        display_as_markdown(combined_table, headers)
    elif args.output == "json":
        display_as_json(combined_table, headers)
    else:
        display_as_markdown(combined_table, headers)

if __name__ == "__main__":
    main()