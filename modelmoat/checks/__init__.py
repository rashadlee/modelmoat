"""Check registry."""

from .apigateway import APIGatewayAIProxyAuthCheck
from .azure_openai import AzureOpenAINetworkCheck
from .bedrock_agentcore import BedrockAgentCoreGatewayCheck
from .datastores import VectorDataStoreCheck
from .iam import AIServiceIAMCheck
from .network import AIVPCEndpointCheck
from .pinecone import PineconeOrgRoleCheck
from .s3 import ModelArtifactBucketCheck
from .sagemaker import SageMakerNetworkCheck
from .vertex_ai import VertexAIReasoningEngineCheck
from .weaviate import WeaviateAnonymousAccessCheck

ALL_CHECKS = [
    SageMakerNetworkCheck(),
    AIServiceIAMCheck(),
    ModelArtifactBucketCheck(),
    AIVPCEndpointCheck(),
    VectorDataStoreCheck(),
    WeaviateAnonymousAccessCheck(),
    PineconeOrgRoleCheck(),
    AzureOpenAINetworkCheck(),
    BedrockAgentCoreGatewayCheck(),
    VertexAIReasoningEngineCheck(),
    APIGatewayAIProxyAuthCheck(),
]
