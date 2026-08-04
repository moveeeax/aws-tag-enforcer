"""aws-tag-enforcer: keep an AWS tagging policy honest, automatically.

The package is split into small, testable pieces:

* :mod:`tag_enforcer.policy`  -- the config-driven required-tag policy engine.
* :mod:`tag_enforcer.events`  -- turn an EventBridge/CloudTrail event into a
  normalized resource reference.
* :mod:`tag_enforcer.tagger`  -- apply tags to a resource (lazy boto3).
* :mod:`tag_enforcer.notify`  -- flag a non-compliant resource to SNS/Slack.
* :mod:`tag_enforcer.handler` -- the Lambda entry point that ties it together.
"""
from .policy import Policy, Evaluation
from .events import ResourceRef, parse_event

__all__ = ["Policy", "Evaluation", "ResourceRef", "parse_event", "__version__"]
__version__ = "0.1.0"
