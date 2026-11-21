-- Defanged sample: load called straight through the global table on a base64 blob.
local blob = "cHJpbnQoMSk="
_G.load(base64decode(blob))()
