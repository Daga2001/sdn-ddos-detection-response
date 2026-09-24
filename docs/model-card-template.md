# Model card template

Complete this document before supplying a model to the inference service.

| Field | Value |
| --- | --- |
| Artifact filename |  |
| SHA-256 |  |
| Training code commit |  |
| scikit-learn version | 1.6.1 expected for the current artifact contract |
| Training / inference Python and NumPy versions | Record both; the container inference service uses Python 3.12 |
| Lab run / topology / image digest | Include GUI run ID and distinguish original versus connected enterprise |
| Validated traffic scenario | Single-source bounded SYN traffic is not distributed DDoS validation |
| Dataset and license |  |
| Training/test split |  |
| Feature order | `packet_count`, `byte_count`, `pktrate`, `byterate`, `ip_proto`, `l4_dst_port` |
| Accuracy / precision / recall / F1 |  |
| Known limitations |  |
| Approved by |  |

The artifact is loaded only after an exact checksum match. A successful load does not prove that the model is accurate, unbiased, or safe for production traffic.
