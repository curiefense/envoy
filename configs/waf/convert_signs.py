#!/usr/bin/env python3
import sys
import json
import yaml

if len(sys.argv) <= 2:
    print("Usage: %s waf-signatures.json out.yaml", file=sys.stderr)
    sys.exit(1)

def parse_signature(s):
    ret = {
        "id": int(s['id']),
        "name": s['name'],
        "msg": s['msg'],
        "operand": s['operand'],
        "severity": int(s['severity']),
        "certainity": int(s['certainity'])
    }
    cat = s['category']
    subcat = s['subcategory']
    if subcat == cat:
        print(cat)
        cat = {cat: {}}
    else:
        subcat = subcat.replace("-","_").replace(" ","_").replace("built_in","builtin")
        cat = {cat: {"subcategory": subcat}}
    ret["category"] = cat
    return ret

data = json.load(open(sys.argv[1]))
signatures = [parse_signature(s) for s in data]
out = {
    "version_info": "0",
    "resources": [{
        "@type": "type.googleapis.com/envoy.config.core.v3.TypedExtensionConfig",
        "name": "waf",
        "typed_config": {
            "@type": "type.googleapis.com/envoy.extensions.filters.http.waf.v3.WAF",
            "signatures": signatures
        }
    }]
}

yaml.safe_dump(out, open(sys.argv[2],"w"))
