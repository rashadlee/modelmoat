"""Check registry."""

from .datastores import VectorDataStoreCheck
from .iam import AIServiceIAMCheck
from .network import AIVPCEndpointCheck
from .s3 import ModelArtifactBucketCheck
from .sagemaker import SageMakerNetworkCheck

ALL_CHECKS = [
    SageMakerNetworkCheck(),
    AIServiceIAMCheck(),
    ModelArtifactBucketCheck(),
    AIVPCEndpointCheck(),
    VectorDataStoreCheck(),
]
