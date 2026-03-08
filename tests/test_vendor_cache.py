



import os
from vendor import vendor_lookup, _load_persistent_cache

# Pick a MAC that is NOT locally administered and is common (replace with one from your network)
MAC = "dell:e6:19:90:00:00".replace("dell", "00")  # <-- replace with real MAC like 98:fa:9b:25:56:67

# 1) remove cache file
if os.path.exists("vendor_cache.json"):
    os.remove("vendor_cache.json")

print("Before:", os.path.exists("vendor_cache.json"))

# 2) lookup should create cache if it finds a vendor
v = vendor_lookup(MAC, local_oui_map=None, use_remote=True)
print("Vendor:", v)

print("After:", os.path.exists("vendor_cache.json"))
print("Cache contents keys:", list(_load_persistent_cache().keys())[:10])