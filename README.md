py-landlock

Minimal Landlock-based filesystem sandbox.

Usage:

```python
from py_landlock import Sandbox

Sandbox(write_paths=["/tmp"]).apply()
```
