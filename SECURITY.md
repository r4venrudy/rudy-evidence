# Security boundaries

Treat scanner reports as untrusted input. This SDK transforms evidence; it does not scan hosts, execute tests, load drivers or decide whether malware exists. Use only reports you are authorized to handle.

Input/output, node, depth and record limits bound ordinary processing. They are not a substitute for service-level resource isolation or deadlines. Native callers must supply valid pointers and lengths. C++ `std::bad_alloc` can propagate; the C ABI contains all exceptions and returns a generic internal-error status.

Redaction recognizes a limited documented set of fields and patterns. It is not a universal data-loss-prevention filter. Review output before sharing it; source digests also reveal equality and permit guessing low-entropy content. Memory is not securely zeroed. The library makes no confidentiality guarantee against the host administrator or process memory inspection.

BLAKE3 integrity is unkeyed and unauthenticated. Anyone can recompute a digest after editing evidence. Use signatures and an independently trusted identity system where authenticity is required. Scope labels and producer names are caller-controlled.

Report defects privately to the repository owner through GitHub's private vulnerability reporting if enabled. Do not post live credentials or private source reports. Reproduce with synthetic fixtures. Version 0.1 is a developer preview without an independent security audit.
