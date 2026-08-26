"""Check registry."""

from .datastores import VectorDataStoreCheck
from .iam import AIServiceIAMCheck
from .network import AIVPCEndpointCheck
from .pinecone import PineconeOrgRoleCheck
from .s3 import ModelArtifactBucketCheck
from .sagemaker import SageMakerNetworkCheck
from .weaviate import WeaviateAnonymousAccessCheck

ALL_CHECKS = [
    SageMakerNetworkCheck(),
    AIServiceIAMCheck(),
    ModelArtifactBucketCheck(),
    AIVPCEndpointCheck(),
    VectorDataStoreCheck(),
    WeaviateAnonymousAccessCheck(),
    PineconeOrgRoleCheck(),
]
